/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * precond: start a bbssd namespace in the state a long write workload leaves
 * it in, without the guest and without the hours that workload takes.
 *
 * A collection or placement study wants the device full and in steady state
 * before it measures, and writing a TiB device full, then over again, takes
 * hours at emulated speed on every run. precond writes the namespace at
 * realize instead, through the entry the FTL thread hands each command to
 * (bb_ftl_process_req()), with the NAND commands untimed: the mapping,
 * lines or reclaim units, valid counts, collection and wear come out as the
 * same commands from the guest would leave them, since the same code made
 * them. No second model of the FTL is built that could reach a state the
 * real one cannot.
 *
 *   seq      every page, in order, 64 pages per command
 *   rand:N   seq, then N times the namespace in single page writes to
 *            uniformly random pages, from precond_seed
 *
 * The blocks read back as whatever the backend holds (zeros unless an
 * earlier run wrote them): treat their content as undefined. They count as
 * written for the Deallocated or Unwritten Logical Block error, and for
 * tag_check, which then checks every mapping before the guest starts.
 * Activity counters (write amplification, media commands, victim order) are
 * cleared afterwards so an experiment measures only itself; wear is kept.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

#define PRECOND_SEQ_PAGES   64

int ftl_precond_parse(const char *spec, int *passes, Error **errp)
{
    const char *n;
    uint64_t v;

    *passes = -1;
    if (!spec || !strcmp(spec, "none")) {
        return 0;
    }
    if (!strcmp(spec, "seq")) {
        *passes = 0;
        return 0;
    }
    if (!strcmp(spec, "rand")) {
        *passes = 1;
        return 0;
    }
    if (strstart(spec, "rand:", &n) && !qemu_strtou64(n, NULL, 10, &v) &&
        v >= 1 && v <= 100) {
        *passes = v;
        return 0;
    }
    error_setg(errp, "femu: precond=%s is not none, seq, rand or rand:N with "
               "N from 1 to 100", spec);
    return -1;
}

/* the blocks per FTL page, which precond writes whole */
static uint64_t precond_page_blocks(struct ssd *ssd, NvmeNamespace *ns)
{
    uint64_t pg = (uint64_t)ssd->sp.secsz * ssd->sp.secs_per_pg;

    return MAX(pg >> ns->lbaf.lbads, 1);
}

static uint16_t precond_write(FemuCtrl *n, NvmeNamespace *ns, uint64_t page,
                              uint64_t npages)
{
    struct ssd *ssd = ns->ssd;
    uint64_t per = precond_page_blocks(ssd, ns);
    NvmeRequest req = { 0 };
    NvmeRwCmd *rw = (NvmeRwCmd *)&req.cmd;

    req.ns = ns;
    req.slba = page * per;
    req.nlb = npages * per;
    req.is_write = 1;
    req.status = NVME_SUCCESS;
    req.cmd_opcode = NVME_CMD_WRITE;
    rw->opcode = NVME_CMD_WRITE;
    rw->nsid = cpu_to_le32(ns->id);
    rw->slba = cpu_to_le64(req.slba);
    rw->nlb = cpu_to_le16(req.nlb - 1);

    if (n->tag_check) {
        bbssd_tag_fetch(n, &req);
    }
    /* the FTL thread's own entry, background collection included */
    bb_ftl_process_req(n, ns, &req);
    if (req.status == NVME_SUCCESS) {
        nvme_mark_written(ns, req.slba, req.nlb);
    }
    if (req.tag) {
        bbssd_tag_complete(n, &req);
    }
    return req.status;
}

/* what a run starts from: activity counters cleared, wear kept */
static void precond_clear_counters(struct ssd *ssd)
{
    ssd->host_write_pages = 0;
    ssd->nand_write_pages = 0;
    ssd->gc_write_pages = 0;
    ssd->gc_copyback_pages = 0;
    ssd->partial_page_writes = 0;
    ssd->gc_stalled_writes = 0;
    ssd->gc_stall_passes = 0;
    ssd->buffer_full_destages = 0;
    ssd->sp.read_cnt = ssd->sp.read_hit_cnt = 0;
    ssd->sp.write_cnt = ssd->sp.write_hit_cnt = 0;
    memset(ssd->media_ops, 0, sizeof(ssd->media_ops));
    memset(ssd->media_plane_ops, 0, sizeof(ssd->media_plane_ops));
    ssd->victim_digest = 0;
    ssd->rcache.hits = ssd->rcache.misses = 0;
    ssd->cmt.hits = ssd->cmt.misses = 0;
}

static int precond_ns(FemuCtrl *n, NvmeNamespace *ns, int passes,
                      Error **errp)
{
    struct ssd *ssd = ns->ssd;
    uint64_t pages = le64_to_cpu(ns->id_ns.nsze) /
                     precond_page_blocks(ssd, ns);
    uint64_t rng = n->precond_seed ? n->precond_seed : 1;
    uint64_t total = pages * (1 + passes), done = 0;
    /* progress for runs long enough to want it */
    uint64_t step = total >= (1ull << 20) ? total / 10 : 0;
    int64_t t0 = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    uint64_t gc_pages, host_pages;
    uint16_t status = NVME_SUCCESS;

    ssd->untimed = true;
    for (uint64_t page = 0; page < pages && !status;
         page += PRECOND_SEQ_PAGES) {
        uint64_t np = MIN(PRECOND_SEQ_PAGES, pages - page);

        status = precond_write(n, ns, page, np);
        done += np;
        if (step && done % step < np) {
            femu_log("precond: namespace %u %" PRIu64 "%%\n", ns->id,
                     done * 100 / total);
        }
    }
    for (uint64_t i = 0; i < pages * passes && !status; i++) {
        /* xorshift64*, so a seed gives the same state on every host */
        rng ^= rng >> 12;
        rng ^= rng << 25;
        rng ^= rng >> 27;
        status = precond_write(n, ns, (rng * 0x2545F4914F6CDD1DULL) % pages,
                               1);
        done++;
        if (step && done % step == 0) {
            femu_log("precond: namespace %u %" PRIu64 "%%\n", ns->id,
                     done * 100 / total);
        }
    }
    if (!status && ssd->write_buffer_cnt) {
        ssd_buffer_destage(ssd, 0, 0);
    }
    ssd->untimed = false;
    if (status) {
        error_setg(errp, "femu: precond of namespace %u failed with status "
                   "0x%x after %" PRIu64 " of %" PRIu64 " pages", ns->id,
                   status, done, total);
        return -1;
    }

    host_pages = ssd->host_write_pages;
    gc_pages = ssd->gc_write_pages;
    precond_clear_counters(ssd);
    femu_log("precond: namespace %u: %" PRIu64 " pages written, %" PRIu64
             " relocated (WAF %.2f) in %" PRId64 " ms\n", ns->id, host_pages,
             gc_pages, host_pages ? (double)(host_pages + gc_pages) /
             host_pages : 0, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - t0);
    if (ssd->tag && ftl_tag_scan(ssd)) {
        error_setg(errp, "femu: precond of namespace %u left mappings that "
                   "tag_check finds wrong; see the log", ns->id);
        return -1;
    }
    return 0;
}

/* Precondition every bbssd namespace; realize calls this last. */
int bbssd_precond(FemuCtrl *n, Error **errp)
{
    int passes;

    if (ftl_precond_parse(n->precond, &passes, errp)) {
        return -1;
    }
    if (n->precond_load) {
        return ftl_state_load(n, n->precond_load, errp);
    }
    if (passes < 0) {
        return 0;
    }
    for (uint32_t i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];

        if (ns->allocated && NS_BBSSD(ns) && ns->ssd &&
            precond_ns(n, ns, passes, errp)) {
            return -1;
        }
    }
    return n->precond_save ? ftl_state_save(n, n->precond_save, errp) : 0;
}
