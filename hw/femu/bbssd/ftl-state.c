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
 * Under FDP the reclaim units, groups and handles follow (state_fdp_*).
 * Supported is the flat page or dftl mapping without streams, hot/cold
 * separation, paced collection or wear-out; realize refuses the rest. The
 * file is native-endian and records the geometry it was saved with, which
 * loading checks.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"
#include "../inc/pqueue.h"

#define STATE_MAGIC     "FEMUFTL1"
#define STATE_VERSION   3       /* 2: page status in a byte; 3: FDP */

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
    uint32_t has_fdp;
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
        n->blk_pe_limit) {
        error_setg(errp, "femu: precond_save and precond_load support the "
                   "page and dftl mappings without streams, hot_cold_sep, "
                   "gc_pace or blk_pe_limit");
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
    h->has_fdp = ssd->fdp_enabled;
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

static bool state_get_wp(struct ssd *ssd, struct write_pointer *wp,
                         const StateWp *s);

/*
 * FDP: a reclaim unit is named by group and index, rg * tt_nru + index, -1
 * for none. Which lines each unit owns is set at init, in a fixed order,
 * and never changes, so the units only need their state.
 */
typedef struct StateFdpHeader {
    uint32_t nrg, nruhs, tt_nru, lines_per_ru;
    int32_t mgmt_type;
    uint32_t pad;
    uint64_t written_bits;
} StateFdpHeader;

typedef struct StateRu {
    int32_t ruh;            /* owning handle, -1 for none */
    int32_t vpc, ipc;
    int32_t line0;          /* the unit's first line, checked on load */
    float utilization, my_cb;
    uint64_t last_invalidated_time;
    uint64_t ruamw;
    StateWp wp;
    int32_t pad;
} StateRu;

typedef struct StateRuh {
    int32_t present;        /* the namespace places into this handle */
    int32_t ru_in_use_cnt, ruh_live_pages_cnt;
    int32_t curr_ru, gc_ru;
    int32_t has_heap;       /* a persistently isolated handle's own heap */
    uint64_t hbmw, mbmw, mbe;
    uint64_t nvme_ruamw, nvme_hbmw, nvme_mbmw, nvme_mbe, event_filter;
} StateRuh;

static int32_t state_ru_id(struct ssd *ssd, FemuReclaimUnit *ru)
{
    return ru ? (int32_t)(ru->rgidx * ssd->rg[0].tt_nru + ru->ruidx) : -1;
}

static FemuReclaimUnit *state_ru(struct ssd *ssd, int32_t id)
{
    uint32_t nru = ssd->rg[0].tt_nru;

    if (id < 0 || (uint32_t)id >= nru * ssd->nrg) {
        return NULL;
    }
    return &ssd->rg[id / nru].rus[id % nru];
}

/* the victim heap a group's policy uses, as fdp_victim_heap() picks it */
static pqueue_t *state_fdp_heap(struct ru_mgmt *rm)
{
    return rm->mgmt_type == GC_GLOBAL_CB ? rm->victim_ru_cb : rm->victim_ru_pq;
}

static bool state_write_ids(FILE *f, int32_t *ids, uint64_t k)
{
    return state_write(f, &k, sizeof(k)) &&
           state_write(f, ids, sizeof(int32_t) * k);
}

static bool state_fdp_save(FILE *f, struct ssd *ssd)
{
    uint32_t nru = ssd->rg[0].tt_nru;
    StateFdpHeader fh = {
        .nrg = ssd->nrg, .nruhs = ssd->nruhs, .tt_nru = nru,
        .lines_per_ru = ssd->sp.lines_per_ru,
        .mgmt_type = ssd->rg[0].ru_mgmt->mgmt_type,
        .written_bits = ssd->fdp_written_bits,
    };
    g_autofree int32_t *ids = g_new(int32_t, nru * ssd->nrg + 1);
    bool ok = state_write(f, &fh, sizeof(fh));

    for (uint32_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;
        pqueue_t *pq = state_fdp_heap(rm);
        FemuReclaimUnit *ru;
        uint64_t k = 0;

        QTAILQ_FOREACH(ru, &rm->free_ru_list, entry) {
            ids[k++] = state_ru_id(ssd, ru);
        }
        ok &= state_write_ids(f, ids, k);
        k = 0;
        QTAILQ_FOREACH(ru, &rm->full_ru_list, entry) {
            ids[k++] = state_ru_id(ssd, ru);
        }
        ok &= state_write_ids(f, ids, k);
        k = 0;
        for (size_t i = 1; i < pq->size; i++) {
            ids[k++] = state_ru_id(ssd, pq->d[i]);
        }
        ok &= state_write_ids(f, ids, k);
        for (uint32_t j = 0; j < nru; j++) {
            FemuReclaimUnit *u = &ssd->rg[g].rus[j];
            StateRu sr = {
                .ruh = u->ruh ? u->ruh->ruhid : -1,
                .vpc = u->vpc, .ipc = u->ipc,
                .line0 = u->lines[0]->id,
                .utilization = u->utilization, .my_cb = u->my_cb,
                .last_invalidated_time = u->last_invalidated_time,
                .ruamw = u->nvme_ru ? u->nvme_ru->ruamw : 0,
            };

            state_put_wp(u->ssd_wptr, &sr.wp);
            ok &= state_write(f, &sr, sizeof(sr));
        }
    }
    for (uint32_t i = 0; i < ssd->nruhs; i++) {
        FemuRuHandle *h = &ssd->ruhs[i];
        StateRuh sh = { .present = h->ruh != NULL };

        if (sh.present) {
            sh.ru_in_use_cnt = h->ru_in_use_cnt;
            sh.ruh_live_pages_cnt = h->ruh_live_pages_cnt;
            sh.curr_ru = state_ru_id(ssd, h->curr_ru);
            sh.gc_ru = state_ru_id(ssd, h->gc_ru);
            sh.has_heap = h->ru_mgmt != NULL;
            sh.hbmw = h->hbmw;
            sh.mbmw = h->mbmw;
            sh.mbe = h->mbe;
            sh.nvme_ruamw = h->ruh->ruamw;
            sh.nvme_hbmw = h->ruh->hbmw;
            sh.nvme_mbmw = h->ruh->mbmw;
            sh.nvme_mbe = h->ruh->mbe;
            sh.event_filter = h->ruh->event_filter;
        }
        ok &= state_write(f, &sh, sizeof(sh));
        if (!sh.present) {
            continue;
        }
        for (uint32_t g = 0; g < ssd->nrg; g++) {
            ids[g] = state_ru_id(ssd, h->rus[g]);
        }
        ok &= state_write(f, ids, sizeof(int32_t) * ssd->nrg);
        if (sh.has_heap) {
            pqueue_t *pq = h->ru_mgmt->victim_ru_pq;
            uint64_t k = 0;

            for (size_t j = 1; j < pq->size; j++) {
                ids[k++] = state_ru_id(ssd, pq->d[j]);
            }
            ok &= state_write_ids(f, ids, k);
        }
    }
    if (ssd->fdp_written) {
        ok &= state_write(f, ssd->fdp_written, BITS_TO_LONGS(
                          ssd->fdp_written_bits) * sizeof(unsigned long));
    }
    return ok;
}

static bool state_read_ids(FILE *f, struct ssd *ssd, int32_t **ids,
                           uint64_t *k)
{
    uint64_t max = (uint64_t)ssd->rg[0].tt_nru * ssd->nrg;

    if (!state_read(f, k, sizeof(*k)) || *k > max) {
        return false;
    }
    g_free(*ids);
    *ids = g_new(int32_t, *k + 1);
    if (!state_read(f, *ids, sizeof(int32_t) * *k)) {
        return false;
    }
    for (uint64_t i = 0; i < *k; i++) {
        if (!state_ru(ssd, (*ids)[i])) {
            return false;
        }
    }
    return true;
}

static int state_fdp_load(FILE *f, struct ssd *ssd, Error **errp)
{
    uint32_t nru = ssd->rg[0].tt_nru;
    g_autofree int32_t *ids = NULL;
    StateFdpHeader fh;
    uint64_t k;

    if (!state_read(f, &fh, sizeof(fh))) {
        goto corrupt;
    }
    if (fh.nrg != ssd->nrg || fh.nruhs != ssd->nruhs || fh.tt_nru != nru ||
        fh.lines_per_ru != ssd->sp.lines_per_ru ||
        fh.mgmt_type != ssd->rg[0].ru_mgmt->mgmt_type ||
        fh.written_bits != ssd->fdp_written_bits) {
        error_setg(errp, "femu: precond_load: the state was saved with "
                   "another FDP configuration (groups, handles, units or "
                   "gc_strategy)");
        return -1;
    }

    for (uint32_t g = 0; g < ssd->nrg; g++) {
        struct ru_mgmt *rm = ssd->rg[g].ru_mgmt;
        pqueue_t *pq = state_fdp_heap(rm);

        /* a fresh FTL has queued no victim yet */
        g_assert(pqueue_size(pq) == 0);
        QTAILQ_INIT(&rm->free_ru_list);
        QTAILQ_INIT(&rm->full_ru_list);
        if (!state_read_ids(f, ssd, &ids, &k)) {
            goto corrupt;
        }
        rm->free_ru_cnt = k;
        for (uint64_t i = 0; i < k; i++) {
            QTAILQ_INSERT_TAIL(&rm->free_ru_list, state_ru(ssd, ids[i]),
                               entry);
        }
        if (!state_read_ids(f, ssd, &ids, &k)) {
            goto corrupt;
        }
        for (uint64_t i = 0; i < k; i++) {
            QTAILQ_INSERT_TAIL(&rm->full_ru_list, state_ru(ssd, ids[i]),
                               entry);
        }
        if (!state_read_ids(f, ssd, &ids, &k)) {
            goto corrupt;
        }
        for (uint32_t j = 0; j < nru; j++) {
            FemuReclaimUnit *u = &ssd->rg[g].rus[j];
            StateRu sr;

            if (!state_read(f, &sr, sizeof(sr)) ||
                sr.ruh >= (int32_t)ssd->nruhs) {
                goto corrupt;
            }
            if (sr.line0 != u->lines[0]->id) {
                error_setg(errp, "femu: precond_load: reclaim unit %u of "
                           "group %u owns other lines here", j, g);
                return -1;
            }
            u->ruh = sr.ruh < 0 ? NULL : &ssd->ruhs[sr.ruh];
            u->vpc = sr.vpc;
            u->ipc = sr.ipc;
            u->utilization = sr.utilization;
            u->my_cb = sr.my_cb;
            u->last_invalidated_time = sr.last_invalidated_time;
            u->reclaiming = false;
            u->pos = 0;
            u->ruh_pos = 0;
            if (u->nvme_ru) {
                u->nvme_ru->ruamw = sr.ruamw;
            }
            if (!state_get_wp(ssd, u->ssd_wptr, &sr.wp)) {
                goto corrupt;
            }
        }
        /* priorities are set: heap order rebuilds the same heap */
        for (uint64_t i = 0; i < k; i++) {
            pqueue_insert(pq, state_ru(ssd, ids[i]));
        }
    }
    for (uint32_t i = 0; i < ssd->nruhs; i++) {
        FemuRuHandle *h = &ssd->ruhs[i];
        StateRuh sh;

        if (!state_read(f, &sh, sizeof(sh)) ||
            sh.present != (h->ruh != NULL) ||
            (sh.present && sh.has_heap != (h->ru_mgmt != NULL))) {
            goto corrupt;
        }
        if (!sh.present) {
            continue;
        }
        h->ru_in_use_cnt = sh.ru_in_use_cnt;
        h->ruh_live_pages_cnt = sh.ruh_live_pages_cnt;
        h->curr_ru = state_ru(ssd, sh.curr_ru);
        h->gc_ru = state_ru(ssd, sh.gc_ru);
        h->hbmw = sh.hbmw;
        h->mbmw = sh.mbmw;
        h->mbe = sh.mbe;
        h->ruh->ruamw = sh.nvme_ruamw;
        h->ruh->hbmw = sh.nvme_hbmw;
        h->ruh->mbmw = sh.nvme_mbmw;
        h->ruh->mbe = sh.nvme_mbe;
        h->ruh->event_filter = sh.event_filter;
        g_free(ids);
        ids = g_new(int32_t, ssd->nrg);
        if (!state_read(f, ids, sizeof(int32_t) * ssd->nrg)) {
            goto corrupt;
        }
        for (uint32_t g = 0; g < ssd->nrg; g++) {
            h->rus[g] = state_ru(ssd, ids[g]);
            h->ruh->rus[g] = h->rus[g] ? h->rus[g]->nvme_ru : &h->no_ru;
        }
        if (sh.has_heap) {
            g_assert(pqueue_size(h->ru_mgmt->victim_ru_pq) == 0);
            if (!state_read_ids(f, ssd, &ids, &k)) {
                goto corrupt;
            }
            for (uint64_t j = 0; j < k; j++) {
                pqueue_insert(h->ru_mgmt->victim_ru_pq, state_ru(ssd, ids[j]));
            }
        }
    }
    if (ssd->fdp_written &&
        !state_read(f, ssd->fdp_written, BITS_TO_LONGS(
                    ssd->fdp_written_bits) * sizeof(unsigned long))) {
        goto corrupt;
    }
    return 0;

corrupt:
    error_setg(errp, "femu: precond_load: the FDP state is truncated or "
               "corrupt");
    return -1;
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
    if (ssd->fdp_enabled) {
        ok &= state_fdp_save(f, ssd);
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
    if (h.has_fdp != want.has_fdp) {
        error_setg(errp, "femu: precond_load: the state was saved with FDP "
                   "%s", h.has_fdp ? "on" : "off");
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
    return ssd->fdp_enabled ? state_fdp_load(f, ssd, errp) : 0;
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
