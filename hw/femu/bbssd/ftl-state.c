/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * precond_save / precond_load: keep the FTL state precond built in a file and
 * start from it on the next run, so one steady state is computed once.
 *
 * The file holds what the FTL keeps between commands: the mapping and its
 * reverse, every page's status, every block's and line's counts and wear,
 * which list each line is on and in what order (the victim queue in heap
 * order, which rebuilds the same heap), the write pointers, the namespace's
 * allocation bitmaps and, with tag_check, the tags and expected versions.
 * Loading it into an FTL just built for the same geometry gives the FTL the
 * saved run had: the same commands then make the same decisions. Caches that
 * only model time, the read cache and the DFTL mapping cache, start empty.
 *
 * Supported is the flat page or dftl mapping without FDP, streams, hot/cold
 * separation, paced collection or wear-out; realize refuses the rest. The
 * file is native-endian and records the geometry it was saved with, which
 * loading checks.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"
#include "../inc/pqueue.h"

#define STATE_MAGIC     "FEMUFTL1"
#define STATE_VERSION   2       /* 2: page status in one byte */

enum {
    LINE_NONE, LINE_FREE, LINE_VICTIM, LINE_FULL, LINE_WP, LINE_LOG_WP,
    LINE_HOT_WP,
};

typedef struct StateHeader {
    char magic[8];
    uint32_t version;
    uint32_t nsid;
    int32_t geo[7];         /* secsz .. nchs, as in struct ssdparams */
    int32_t spare_lines;
    uint64_t tt_pgs;
    uint64_t nsze;
    uint32_t lbads;
    uint32_t has_tag;
    char mapping[16];
} StateHeader;

typedef struct StateBlock {
    int32_t ipc, vpc, wp;
    uint32_t erase_cnt;
    uint64_t read_cnt;
} StateBlock;

typedef struct StateLine {
    int32_t ipc, vpc;
    int32_t where;          /* LINE_* */
    uint8_t retired, spare, pad[2];
    uint64_t close_time, open_time, close_seq, stream_tag;
} StateLine;

typedef struct StateWp {
    int32_t line;           /* -1: no line */
    int32_t ch, lun, pg, blk, pl;
} StateWp;

typedef struct StateCounters {
    uint64_t total_erases;
    uint64_t next_close_seq;
    uint64_t gc_rng;
    uint64_t wl_credit;
    int32_t free_line_cnt, full_line_cnt, retired_line_cnt, wl_on;
} StateCounters;

/* what save and load refuse, for realize to say before any work is done */
bool ftl_state_supported(FemuCtrl *n, Error **errp)
{
    const char *map = n->bb_params.mapping_scheme;

    if ((map && strcmp(map, "page") && strcmp(map, "dftl")) || n->streams ||
        n->bb_params.hot_cold_sep || n->bb_params.gc_pace ||
        n->blk_pe_limit || (n->subsys && n->subsys->params.fdp.enabled)) {
        error_setg(errp, "femu: precond_save and precond_load support the "
                   "page and dftl mappings without FDP, streams, "
                   "hot_cold_sep, gc_pace or blk_pe_limit");
        return false;
    }
    return true;
}

static void state_header(struct ssd *ssd, NvmeNamespace *ns, StateHeader *h)
{
    struct ssdparams *spp = &ssd->sp;

    memset(h, 0, sizeof(*h));
    memcpy(h->magic, STATE_MAGIC, sizeof(h->magic));
    h->version = STATE_VERSION;
    h->nsid = ns->id;
    h->geo[0] = spp->secsz;
    h->geo[1] = spp->secs_per_pg;
    h->geo[2] = spp->pgs_per_blk;
    h->geo[3] = spp->blks_per_pl;
    h->geo[4] = spp->pls_per_lun;
    h->geo[5] = spp->luns_per_ch;
    h->geo[6] = spp->nchs;
    h->spare_lines = ssd->spare_lines;
    h->tt_pgs = spp->tt_pgs;
    h->nsze = le64_to_cpu(ns->id_ns.nsze);
    h->lbads = ns->lbaf.lbads;
    h->has_tag = ssd->tag != NULL;
    pstrcpy(h->mapping, sizeof(h->mapping), ssd->mapping->name);
}

/* call @fn on every block, in channel, LUN, plane, block order */
#define FOR_EACH_BLOCK(ssd, blkp)                                           \
    for (int ch_ = 0; ch_ < (ssd)->sp.nchs; ch_++)                          \
        for (int lun_ = 0; lun_ < (ssd)->sp.luns_per_ch; lun_++)            \
            for (int pl_ = 0; pl_ < (ssd)->sp.pls_per_lun; pl_++)           \
                for (int b_ = 0; b_ < (ssd)->sp.blks_per_pl &&              \
                     ((blkp) = &(ssd)->ch[ch_].lun[lun_].pl[pl_].blk[b_]);  \
                     b_++)

static int state_line_where(struct ssd *ssd, struct line *line)
{
    if (ssd->wp.curline == line) {
        return LINE_WP;
    }
    if (ssd->log_wp.curline == line) {
        return LINE_LOG_WP;
    }
    if (ssd->hot_wp.curline == line) {
        return LINE_HOT_WP;
    }
    return LINE_NONE;   /* the lists are walked separately */
}

static void state_put_wp(struct write_pointer *wp, StateWp *s)
{
    s->line = wp->curline ? wp->curline->id : -1;
    s->ch = wp->ch;
    s->lun = wp->lun;
    s->pg = wp->pg;
    s->blk = wp->blk;
    s->pl = wp->pl;
}

static bool state_write(FILE *f, const void *p, size_t len)
{
    return fwrite(p, 1, len, f) == len;
}

static bool state_read(FILE *f, void *p, size_t len)
{
    return fread(p, 1, len, f) == len;
}

static bool state_save_ns(FILE *f, struct ssd *ssd, NvmeNamespace *ns)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ftl_tag_arrays tags;
    struct nand_block *blk;
    StateHeader h;
    StateCounters ctr = { 0 };
    StateWp wps[3];
    g_autofree StateLine *lines = g_new0(StateLine, lm->tt_lines);
    g_autofree int32_t *order = g_new(int32_t, lm->tt_lines + 3);
    g_autofree uint8_t *status = NULL;
    struct line *line;
    uint64_t k = 0;
    bool ok = true;

    state_header(ssd, ns, &h);
    ok &= state_write(f, &h, sizeof(h));
    ok &= state_write(f, ssd->maptbl, sizeof(struct ppa) * ssd->sp.tt_pgs);
    ok &= state_write(f, ssd->rmap, sizeof(uint64_t) * ssd->sp.tt_pgs);

    status = g_new(uint8_t, ssd->sp.pgs_per_blk);
    FOR_EACH_BLOCK(ssd, blk) {
        StateBlock sb = {
            .ipc = blk->ipc, .vpc = blk->vpc, .wp = blk->wp,
            .erase_cnt = blk->erase_cnt, .read_cnt = blk->read_cnt,
        };

        for (int i = 0; i < ssd->sp.pgs_per_blk; i++) {
            status[i] = blk->pg[i].status;
        }
        ok &= state_write(f, &sb, sizeof(sb));
        ok &= state_write(f, status, ssd->sp.pgs_per_blk);
    }

    for (int i = 0; i < lm->tt_lines; i++) {
        line = &lm->lines[i];
        lines[i] = (StateLine) {
            .ipc = line->ipc, .vpc = line->vpc,
            .where = state_line_where(ssd, line),
            .retired = line->retired, .spare = line->spare,
            .close_time = line->close_time, .open_time = line->open_time,
            .close_seq = line->close_seq, .stream_tag = line->stream_tag,
        };
    }
    /* list order: free, full, victim heap; each preceded by its length */
    QTAILQ_FOREACH(line, &lm->free_line_list, entry) {
        lines[line->id].where = LINE_FREE;
        order[k++] = line->id;
    }
    ok &= state_write(f, &k, sizeof(k));
    ok &= state_write(f, order, sizeof(int32_t) * k);
    k = 0;
    QTAILQ_FOREACH(line, &lm->full_line_list, entry) {
        lines[line->id].where = LINE_FULL;
        order[k++] = line->id;
    }
    ok &= state_write(f, &k, sizeof(k));
    ok &= state_write(f, order, sizeof(int32_t) * k);
    k = 0;
    for (size_t i = 1; i < lm->victim_line_pq->size; i++) {
        line = lm->victim_line_pq->d[i];
        lines[line->id].where = LINE_VICTIM;
        order[k++] = line->id;
    }
    ok &= state_write(f, &k, sizeof(k));
    ok &= state_write(f, order, sizeof(int32_t) * k);
    ok &= state_write(f, lines, sizeof(StateLine) * lm->tt_lines);

    state_put_wp(&ssd->wp, &wps[0]);
    state_put_wp(&ssd->log_wp, &wps[1]);
    state_put_wp(&ssd->hot_wp, &wps[2]);
    ok &= state_write(f, wps, sizeof(wps));

    ctr.total_erases = ssd->total_erases;
    ctr.next_close_seq = lm->next_close_seq;
    ctr.gc_rng = ssd->gc_rng;
    ctr.wl_credit = ssd->wl_credit;
    ctr.free_line_cnt = lm->free_line_cnt;
    ctr.full_line_cnt = lm->full_line_cnt;
    ctr.retired_line_cnt = lm->retired_line_cnt;
    ctr.wl_on = ssd->wl_on;
    ok &= state_write(f, &ctr, sizeof(ctr));

    ok &= state_write(f, ns->util, BITS_TO_LONGS(ns->ns_blks) *
                      sizeof(unsigned long));
    ok &= state_write(f, ns->uncorrectable, BITS_TO_LONGS(ns->ns_blks) *
                      sizeof(unsigned long));
    if (ssd->tag) {
        ftl_tag_get_arrays(ssd, &tags);
        ok &= state_write(f, tags.page, sizeof(uint64_t) * ssd->sp.tt_pgs);
        ok &= state_write(f, tags.state, sizeof(uint64_t) * tags.nr_lpns);
        ok &= state_write(f, tags.completed, sizeof(uint32_t) * tags.nr_lpns);
    }
    return ok;
}

static bool state_get_wp(struct ssd *ssd, struct write_pointer *wp,
                         const StateWp *s)
{
    if (s->line >= ssd->lm.tt_lines) {
        return false;
    }
    wp->curline = s->line < 0 ? NULL : &ssd->lm.lines[s->line];
    wp->ch = s->ch;
    wp->lun = s->lun;
    wp->pg = s->pg;
    wp->blk = s->blk;
    wp->pl = s->pl;
    return true;
}

static bool state_read_order(FILE *f, struct ssd *ssd, int32_t **order,
                             uint64_t *k)
{
    if (!state_read(f, k, sizeof(*k)) || *k > (uint64_t)ssd->lm.tt_lines) {
        return false;
    }
    *order = g_new(int32_t, *k + 1);
    if (!state_read(f, *order, sizeof(int32_t) * *k)) {
        return false;
    }
    for (uint64_t i = 0; i < *k; i++) {
        if ((*order)[i] < 0 || (*order)[i] >= ssd->lm.tt_lines) {
            return false;
        }
    }
    return true;
}

static int state_load_ns(FILE *f, struct ssd *ssd, NvmeNamespace *ns,
                         Error **errp)
{
    struct line_mgmt *lm = &ssd->lm;
    struct ftl_tag_arrays tags;
    struct nand_block *blk;
    StateHeader want, h;
    StateCounters ctr;
    StateWp wps[3];
    g_autofree StateLine *lines = g_new(StateLine, lm->tt_lines);
    g_autofree int32_t *free_order = NULL;
    g_autofree int32_t *full_order = NULL;
    g_autofree int32_t *victim_order = NULL;
    g_autofree uint8_t *status = g_new(uint8_t, ssd->sp.pgs_per_blk);
    uint64_t nfree, nfull, nvictim;
    bool ok = true;

    state_header(ssd, ns, &want);
    if (!state_read(f, &h, sizeof(h)) ||
        memcmp(h.magic, STATE_MAGIC, sizeof(h.magic)) ||
        h.version != STATE_VERSION) {
        error_setg(errp, "femu: precond_load: not a FEMU FTL state file of "
                   "version %d", STATE_VERSION);
        return -1;
    }
    if (h.nsid != want.nsid || memcmp(h.geo, want.geo, sizeof(h.geo)) ||
        h.spare_lines != want.spare_lines || h.tt_pgs != want.tt_pgs ||
        h.nsze != want.nsze || h.lbads != want.lbads ||
        strcmp(h.mapping, want.mapping)) {
        error_setg(errp, "femu: precond_load: namespace %u was saved with "
                   "another geometry, size, LBA format or mapping",
                   ns->id);
        return -1;
    }
    if (h.has_tag != want.has_tag) {
        error_setg(errp, "femu: precond_load: the state was saved with "
                   "tag_check %s; set it the same way to load it",
                   h.has_tag ? "on" : "off");
        return -1;
    }

    ok &= state_read(f, ssd->maptbl, sizeof(struct ppa) * ssd->sp.tt_pgs);
    ok &= state_read(f, ssd->rmap, sizeof(uint64_t) * ssd->sp.tt_pgs);
    FOR_EACH_BLOCK(ssd, blk) {
        StateBlock sb;

        ok &= state_read(f, &sb, sizeof(sb));
        ok &= state_read(f, status, ssd->sp.pgs_per_blk);
        if (!ok) {
            break;
        }
        blk->ipc = sb.ipc;
        blk->vpc = sb.vpc;
        blk->wp = sb.wp;
        blk->erase_cnt = sb.erase_cnt;
        blk->read_cnt = sb.read_cnt;
        for (int i = 0; i < ssd->sp.pgs_per_blk; i++) {
            blk->pg[i].status = status[i];
        }
    }

    ok = ok && state_read_order(f, ssd, &free_order, &nfree) &&
         state_read_order(f, ssd, &full_order, &nfull) &&
         state_read_order(f, ssd, &victim_order, &nvictim) &&
         state_read(f, lines, sizeof(StateLine) * lm->tt_lines) &&
         state_read(f, wps, sizeof(wps)) &&
         state_read(f, &ctr, sizeof(ctr));
    if (!ok) {
        error_setg(errp, "femu: precond_load: the state file is truncated "
                   "or corrupt");
        return -1;
    }

    /* the FTL was just built: empty its lists and take the saved ones */
    g_assert(pqueue_size(lm->victim_line_pq) == 0);
    QTAILQ_INIT(&lm->free_line_list);
    QTAILQ_INIT(&lm->full_line_list);
    for (int i = 0; i < lm->tt_lines; i++) {
        struct line *line = &lm->lines[i];

        line->ipc = lines[i].ipc;
        line->vpc = lines[i].vpc;
        line->retired = lines[i].retired;
        line->spare = lines[i].spare;
        line->reclaiming = false;
        line->close_time = lines[i].close_time;
        line->open_time = lines[i].open_time;
        line->close_seq = lines[i].close_seq;
        line->stream_tag = lines[i].stream_tag;
        line->pos = 0;
    }
    for (uint64_t i = 0; i < nfree; i++) {
        QTAILQ_INSERT_TAIL(&lm->free_line_list, &lm->lines[free_order[i]],
                           entry);
    }
    for (uint64_t i = 0; i < nfull; i++) {
        QTAILQ_INSERT_TAIL(&lm->full_line_list, &lm->lines[full_order[i]],
                           entry);
    }
    /* inserted in heap order, no entry moves: the same heap comes back */
    for (uint64_t i = 0; i < nvictim; i++) {
        pqueue_insert(lm->victim_line_pq, &lm->lines[victim_order[i]]);
    }
    if (!state_get_wp(ssd, &ssd->wp, &wps[0]) ||
        !state_get_wp(ssd, &ssd->log_wp, &wps[1]) ||
        !state_get_wp(ssd, &ssd->hot_wp, &wps[2])) {
        error_setg(errp, "femu: precond_load: the state file is corrupt");
        return -1;
    }
    ssd->total_erases = ctr.total_erases;
    lm->next_close_seq = ctr.next_close_seq;
    ssd->gc_rng = ctr.gc_rng;
    ssd->wl_credit = ctr.wl_credit;
    lm->free_line_cnt = ctr.free_line_cnt;
    lm->full_line_cnt = ctr.full_line_cnt;
    lm->retired_line_cnt = ctr.retired_line_cnt;
    ssd->wl_on = ctr.wl_on;

    ok = state_read(f, ns->util, BITS_TO_LONGS(ns->ns_blks) *
                    sizeof(unsigned long)) &&
         state_read(f, ns->uncorrectable, BITS_TO_LONGS(ns->ns_blks) *
                    sizeof(unsigned long));
    if (ok && ssd->tag) {
        ftl_tag_get_arrays(ssd, &tags);
        ok = state_read(f, tags.page, sizeof(uint64_t) * ssd->sp.tt_pgs) &&
             state_read(f, tags.state, sizeof(uint64_t) * tags.nr_lpns) &&
             state_read(f, tags.completed,
                        sizeof(uint32_t) * tags.nr_lpns);
    }
    if (!ok) {
        error_setg(errp, "femu: precond_load: the state file is truncated");
        return -1;
    }
    return 0;
}

/* every bbssd namespace of @n, in namespace order */
#define FOR_EACH_BB_NS(n, ns)                                               \
    for (uint32_t i_ = 0; (n)->namespaces && i_ < (n)->namespace_limit;     \
         i_++)                                                              \
        if (((ns) = &(n)->namespaces[i_])->allocated && NS_BBSSD(ns) &&     \
            (ns)->ssd)

int ftl_state_save(FemuCtrl *n, const char *path, Error **errp)
{
    NvmeNamespace *ns;
    FILE *f = fopen(path, "wb");
    bool ok = true;

    if (!f) {
        error_setg_errno(errp, errno, "femu: precond_save: %s", path);
        return -1;
    }
    FOR_EACH_BB_NS(n, ns) {
        ok = ok && state_save_ns(f, ns->ssd, ns);
    }
    if (fclose(f) || !ok) {
        error_setg(errp, "femu: precond_save: cannot write %s", path);
        unlink(path);
        return -1;
    }
    femu_log("precond: FTL state saved to %s\n", path);
    return 0;
}

int ftl_state_load(FemuCtrl *n, const char *path, Error **errp)
{
    NvmeNamespace *ns;
    FILE *f = fopen(path, "rb");

    if (!f) {
        error_setg_errno(errp, errno, "femu: precond_load: %s", path);
        return -1;
    }
    FOR_EACH_BB_NS(n, ns) {
        if (state_load_ns(f, ns->ssd, ns, errp)) {
            fclose(f);
            return -1;
        }
        if (ns->ssd->tag && ftl_tag_scan(ns->ssd)) {
            fclose(f);
            error_setg(errp, "femu: precond_load: tag_check finds mappings "
                       "of namespace %u wrong; see the log", ns->id);
            return -1;
        }
    }
    if (fgetc(f) != EOF) {
        fclose(f);
        error_setg(errp, "femu: precond_load: %s holds more namespaces than "
                   "this controller has", path);
        return -1;
    }
    fclose(f);
    femu_log("precond: FTL state loaded from %s\n", path);
    return 0;
}
