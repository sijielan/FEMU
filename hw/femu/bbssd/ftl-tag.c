/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * tag_check: catch bbssd FTL bugs that FEMU's data does not show.
 *
 * The backend keeps data by LBA, not by physical page, so a mapping that
 * points at the wrong page, a page collection lost or an erase that left a
 * mapping behind all read back correct data. Instead the FTL keeps a tag
 * with each physical page, the logical page and a version, as a device
 * keeps the logical address in a page's spare area: a program writes it, a
 * relocation copies it and an erase clears it. A read reports the tag of the
 * page the mapping names.
 *
 * What the tag ought to be does not come from the FTL. The I/O layer numbers
 * the commands that change each logical page as it fetches them (issued)
 * and records, as each completes, the oldest version a later read may still
 * see (completed). A read may then see any version from completed when it
 * was fetched to issued when it completes: NVMe orders no command against
 * one it overlaps. Commands to one page that overlap each other form a
 * group, and completed only moves when the group's last command completes,
 * to its first, since any of them may have landed last.
 *
 * Per logical page the I/O layer keeps a state word and a completed word,
 * and per physical page the FTL keeps a tag:
 *
 *   state:     issued:24 | group first:24 | in flight:13 | group flags:3
 *   completed: version:24 | TRIM | UNTRACKED | WRITTEN
 *   tag:       logical page:40 | version:24
 *
 * Versions wrap modulo 2^24 and are compared as distances from completed;
 * 0 is no version. A deallocate takes a version but writes no tag, and a
 * read finding no mapping is right only if the page was never written, was
 * last deallocated, or saw a command overlap it. Copy destinations are not
 * modelled: they are left untracked until the next write completes.
 *
 * The check is a few comparisons, made as the read completes. Only failures
 * cost more: the first are logged with the logical and physical page.
 */
#include "qemu/osdep.h"
#include "ftl.h"
#include "ftl-internal.h"

#define TAG_VER_BITS        24
#define TAG_VER_MASK        ((1u << TAG_VER_BITS) - 1)

/* state word */
#define ST_GMIN_SHIFT       24
#define ST_INFL_SHIFT       48
#define ST_INFL_MAX         ((1ull << 13) - 1)
#define ST_INFL_ONE         (1ull << ST_INFL_SHIFT)
#define ST_GTRIM            (1ull << 61)
#define ST_GUNTR            (1ull << 62)
#define ST_GFAIL            (1ull << 63)
#define ST_GFLAGS           (ST_GTRIM | ST_GUNTR | ST_GFAIL)

/* completed word */
#define CP_TRIM             (1u << 24)
#define CP_UNTRACKED        (1u << 25)
#define CP_WRITTEN          (1u << 26)

#define TAG_LOG_MAX         16

enum {
    TAG_OP_READ = 1,
    TAG_OP_WRITE,
    TAG_OP_TRIM,
    TAG_OP_UNTRACKED,
};

struct ftl_tag {
    uint64_t nr_lpns;
    uint64_t *page;         /* per physical page */
    uint64_t *state;        /* per logical page */
    uint32_t *completed;    /* per logical page */
    uint64_t checked;
    uint64_t errors;
    uint64_t skipped;
    uint64_t injected;
    bool overflow;          /* too many commands overlapped to keep count */
};

typedef struct FtlTagRead {
    uint32_t lo;            /* completed when fetched */
    uint32_t hi0;           /* issued when fetched */
    bool racy;              /* a command overlapped the read */
    uint64_t tag;           /* what the FTL found */
    uint64_t pgidx;
} FtlTagRead;

typedef struct FtlTagRange {
    uint64_t start, end;    /* logical pages, inclusive */
} FtlTagRange;

typedef struct FtlTagReq {
    struct ssd *ssd;
    int op;
    uint32_t nr_ranges;
    FtlTagRange *ranges;
    uint32_t *ver;          /* WRITE: per page of ranges[0] */
    FtlTagRead *rec;        /* READ: per page of ranges[0] */
} FtlTagReq;

static inline uint32_t tag_next_ver(uint32_t v)
{
    v = (v + 1) & TAG_VER_MASK;
    return v ? v : 1;
}

/* is @v within [@lo, @hi], all modulo 2^24 */
static inline bool tag_ver_between(uint32_t lo, uint32_t v, uint32_t hi)
{
    return ((v - lo) & TAG_VER_MASK) <= ((hi - lo) & TAG_VER_MASK);
}

void ftl_tag_init(struct ssd *ssd)
{
    struct ftl_tag *t = g_new0(struct ftl_tag, 1);

    t->nr_lpns = ssd->sp.tt_pgs;
    t->page = g_new(uint64_t, ssd->sp.tt_pgs);
    memset(t->page, 0xff, sizeof(uint64_t) * ssd->sp.tt_pgs);
    t->state = g_new0(uint64_t, t->nr_lpns);
    t->completed = g_new0(uint32_t, t->nr_lpns);
    ssd->tag = t;
}

void ftl_tag_free(struct ssd *ssd)
{
    struct ftl_tag *t = ssd->tag;

    if (!t) {
        return;
    }
    g_free(t->page);
    g_free(t->state);
    g_free(t->completed);
    g_free(t);
    ssd->tag = NULL;
}

/*
 * Format and Sanitize deallocate every page with the I/O stopped, as a
 * deallocate of its own that completes at once. A command still waiting to
 * complete stays counted in flight, so its page's group now takes in the
 * deallocate too.
 */
void ftl_tag_reset(struct ssd *ssd)
{
    struct ftl_tag *t = ssd->tag;

    if (!t) {
        return;
    }
    for (uint64_t lpn = 0; lpn < t->nr_lpns; lpn++) {
        uint64_t st = t->state[lpn];
        uint32_t v = tag_next_ver(st & TAG_VER_MASK);

        if (st >> ST_INFL_SHIFT & ST_INFL_MAX) {
            t->state[lpn] = (st & ~(uint64_t)TAG_VER_MASK) | v | ST_GTRIM;
        } else {
            t->state[lpn] = v | (uint64_t)v << ST_GMIN_SHIFT;
        }
        t->completed[lpn] = v | CP_TRIM | CP_WRITTEN;
    }
}

/* qtest: fire injection @point once, if it is the one asked for */
bool ftl_tag_inject(struct ssd *ssd, int point)
{
    if (likely(qatomic_read(&ssd->n->tag_inject) != point) ||
        !ssd->tag || qatomic_read(&ssd->tag->injected)) {
        return false;
    }
    qatomic_inc(&ssd->tag->injected);
    return true;
}

/*
 * The tag a program of @lpn for @req writes: the version the I/O layer gave
 * the command for that page, or none for a command it does not model.
 */
uint64_t ftl_tag_value(struct ssd *ssd, NvmeRequest *req, uint64_t lpn)
{
    FtlTagReq *tr = req ? req->tag : NULL;
    uint64_t ver = 0;

    if (tr && tr->op == TAG_OP_WRITE && lpn >= tr->ranges[0].start &&
        lpn <= tr->ranges[0].end) {
        ver = tr->ver[lpn - tr->ranges[0].start];
    }
    return lpn << TAG_VER_BITS | ver;
}

void ftl_tag_program(struct ssd *ssd, struct ppa *ppa, uint64_t tag)
{
    ssd->tag->page[ppa2pgidx(ssd, ppa)] = tag;
}

void ftl_tag_move(struct ssd *ssd, struct ppa *from, struct ppa *to)
{
    ssd->tag->page[ppa2pgidx(ssd, to)] = ssd->tag->page[ppa2pgidx(ssd, from)];
}

/*
 * Clear the tags of the block @blk names. Left in place, a mapping that
 * still points into the block would read a tag that may well match, and once
 * the block holds other pages a failure would name the wrong logical page.
 */
void ftl_tag_erase(struct ssd *ssd, struct ppa *blk)
{
    struct ppa ppa = *blk;

    for (ppa.g.pg = 0; ppa.g.pg < ssd->sp.pgs_per_blk; ppa.g.pg++) {
        ssd->tag->page[ppa2pgidx(ssd, &ppa)] = FTL_TAG_ERASED;
    }
}

/*
 * Note what a read of @lpn for @req found: the page @ppa names, or with @ppa
 * NULL the write buffer's tag @buffered, or nothing mapped.
 */
void ftl_tag_read(struct ssd *ssd, NvmeRequest *req, uint64_t lpn,
                  struct ppa *ppa, uint64_t buffered)
{
    FtlTagReq *tr = req->tag;
    FtlTagRead *rec;

    if (!tr || tr->op != TAG_OP_READ || lpn < tr->ranges[0].start ||
        lpn > tr->ranges[0].end) {
        return;
    }
    rec = &tr->rec[lpn - tr->ranges[0].start];
    if (!ppa) {
        rec->tag = buffered;
        rec->pgidx = UINT64_MAX;
    } else if (!mapped_ppa(ppa) || !valid_ppa(ssd, ppa)) {
        rec->tag = FTL_TAG_UNMAPPED;
        rec->pgidx = UINT64_MAX;
    } else {
        rec->pgidx = ppa2pgidx(ssd, ppa);
        rec->tag = ssd->tag->page[rec->pgidx];
    }
}

/* number a command @op that changes @lpn; 0 when it cannot be counted */
static uint32_t tag_op_start(struct ftl_tag *t, uint64_t lpn, int op)
{
    uint64_t old = qatomic_read(&t->state[lpn]);
    uint64_t new, prev;
    uint32_t v;

    for (;;) {
        if (((old >> ST_INFL_SHIFT) & ST_INFL_MAX) == ST_INFL_MAX) {
            if (!qatomic_xchg(&t->overflow, true)) {
                femu_err("tag_check: more than %llu commands overlap on page "
                         "%" PRIu64 "; it is no longer checked\n",
                         ST_INFL_MAX, lpn);
            }
            qatomic_fetch_or(&t->completed[lpn], CP_UNTRACKED);
            return 0;
        }
        v = tag_next_ver(old & TAG_VER_MASK);
        new = (old & ~(uint64_t)TAG_VER_MASK) | v;
        if (!(old >> ST_INFL_SHIFT & ST_INFL_MAX)) {
            /* the first of a group */
            new &= ~(((uint64_t)TAG_VER_MASK << ST_GMIN_SHIFT) | ST_GFLAGS);
            new |= (uint64_t)v << ST_GMIN_SHIFT;
        }
        new += ST_INFL_ONE;
        if (op == TAG_OP_TRIM) {
            new |= ST_GTRIM;
        } else if (op == TAG_OP_UNTRACKED) {
            new |= ST_GUNTR;
        }
        prev = qatomic_cmpxchg(&t->state[lpn], old, new);
        if (prev == old) {
            return v;
        }
        old = prev;
    }
}

/* a command on @lpn completed; the group's last one sets completed */
static void tag_op_end(struct ftl_tag *t, uint64_t lpn, bool failed)
{
    uint64_t old = qatomic_read(&t->state[lpn]);
    uint64_t new, prev;
    uint32_t cp;

    for (;;) {
        if (!(old >> ST_INFL_SHIFT & ST_INFL_MAX)) {
            return;     /* not counted, as when the count overflowed */
        }
        new = old - ST_INFL_ONE;
        if (failed) {
            new |= ST_GFAIL;
        }
        prev = qatomic_cmpxchg(&t->state[lpn], old, new);
        if (prev == old) {
            break;
        }
        old = prev;
    }
    if (new >> ST_INFL_SHIFT & ST_INFL_MAX) {
        return;
    }
    cp = (new >> ST_GMIN_SHIFT & TAG_VER_MASK) | CP_WRITTEN;
    if (new & ST_GTRIM) {
        cp |= CP_TRIM;
    }
    /* a failed command may have programmed some of its pages */
    if (new & (ST_GUNTR | ST_GFAIL)) {
        cp |= CP_UNTRACKED;
    }
    qatomic_set(&t->completed[lpn], cp);
}

static void tag_add_range(FtlTagReq *tr, uint64_t start, uint64_t end)
{
    tr->ranges = g_renew(FtlTagRange, tr->ranges, tr->nr_ranges + 1);
    tr->ranges[tr->nr_ranges].start = start;
    tr->ranges[tr->nr_ranges].end = end;
    tr->nr_ranges++;
}

/*
 * The I/O layer fetched @req, a command for a bbssd namespace with
 * tag_check, and it passed validation: number its pages, or for a read note
 * what it may see.
 */
void bbssd_tag_fetch(FemuCtrl *n, NvmeRequest *req)
{
    struct ssd *ssd = req->ns->ssd;
    struct ftl_tag *t = ssd->tag;
    const NvmeRwCmd *rw = (const NvmeRwCmd *)&req->cmd;
    uint64_t start, end;
    FtlTagReq *tr;
    int op;

    if (!t) {
        return;
    }
    switch (req->cmd.opcode) {
    case NVME_CMD_READ:
        op = TAG_OP_READ;
        break;
    case NVME_CMD_WRITE:
        op = TAG_OP_WRITE;
        break;
    case NVME_CMD_WRITE_ZEROES:
        /* with the bit the pages are deallocated, without it programmed */
        op = le16_to_cpu(rw->control) & NVME_WZ_DEAC ? TAG_OP_TRIM
                                                      : TAG_OP_WRITE;
        break;
    case NVME_CMD_DSM:
        if (!req->dsm_ranges) {
            return;
        }
        op = TAG_OP_TRIM;
        break;
    case NVME_CMD_COPY:
        op = TAG_OP_UNTRACKED;
        break;
    default:
        return;
    }

    tr = g_new0(FtlTagReq, 1);
    tr->ssd = ssd;
    tr->op = op;
    if (req->cmd.opcode == NVME_CMD_DSM) {
        for (uint32_t i = 0; i < req->dsm_nr_ranges; i++) {
            ssd_lpn_range(ssd, req, le64_to_cpu(req->dsm_ranges[i].slba),
                          le32_to_cpu(req->dsm_ranges[i].nlb), &start, &end);
            if (le32_to_cpu(req->dsm_ranges[i].nlb) && end < t->nr_lpns) {
                tag_add_range(tr, start, end);
            }
        }
    } else {
        uint64_t slba = req->slba, nlb = req->nlb;

        if (req->cmd.opcode == NVME_CMD_WRITE_ZEROES) {
            slba = le64_to_cpu(rw->slba);
            nlb = le16_to_cpu(rw->nlb) + 1;
        }
        ssd_lpn_range(ssd, req, slba, nlb, &start, &end);
        if (nlb && end < t->nr_lpns) {
            tag_add_range(tr, start, end);
        }
    }
    if (!tr->nr_ranges) {
        g_free(tr);
        return;
    }

    if (op == TAG_OP_READ) {
        uint64_t len = tr->ranges[0].end - tr->ranges[0].start + 1;

        tr->rec = g_new(FtlTagRead, len);
        for (uint64_t i = 0; i < len; i++) {
            uint64_t lpn = tr->ranges[0].start + i;
            uint64_t st;

            tr->rec[i].lo = qatomic_read(&t->completed[lpn]);
            st = qatomic_read(&t->state[lpn]);
            tr->rec[i].hi0 = st & TAG_VER_MASK;
            tr->rec[i].racy = st >> ST_INFL_SHIFT & ST_INFL_MAX;
            tr->rec[i].tag = FTL_TAG_UNMAPPED;
            tr->rec[i].pgidx = UINT64_MAX;
        }
    } else if (op == TAG_OP_WRITE) {
        uint64_t len = tr->ranges[0].end - tr->ranges[0].start + 1;

        tr->ver = g_new(uint32_t, len);
        for (uint64_t i = 0; i < len; i++) {
            tr->ver[i] = tag_op_start(t, tr->ranges[0].start + i, op);
        }
    } else {
        for (uint32_t r = 0; r < tr->nr_ranges; r++) {
            for (uint64_t lpn = tr->ranges[r].start;
                 lpn <= tr->ranges[r].end; lpn++) {
                tag_op_start(t, lpn, op);
            }
        }
    }
    req->tag = tr;
}

static void tag_report(struct ftl_tag *t, NvmeRequest *req, uint64_t lpn,
                       const FtlTagRead *rec, uint32_t hi, const char *why)
{
    uint64_t nr = qatomic_fetch_inc(&t->errors);

    if (nr >= TAG_LOG_MAX) {
        return;
    }
    femu_err("tag_check: cid %u nsid %u lpn %" PRIu64 ": %s (expected "
             "version %u..%u%s%s, found %s lpn %" PRIu64 " version %u, "
             "page %" PRId64 ")\n", req->cqe.cid, req->ns->id, lpn, why,
             rec->lo & TAG_VER_MASK, hi,
             rec->lo & CP_TRIM ? " or unmapped" : "",
             rec->racy ? ", overlapped" : "",
             rec->tag == FTL_TAG_ERASED ? "erased" :
             rec->tag == FTL_TAG_UNMAPPED ? "unmapped" : "tag",
             rec->tag < FTL_TAG_UNMAPPED ? rec->tag >> TAG_VER_BITS : 0,
             rec->tag < FTL_TAG_UNMAPPED ? (uint32_t)rec->tag & TAG_VER_MASK
                                         : 0,
             rec->pgidx == UINT64_MAX ? (int64_t)-1 : (int64_t)rec->pgidx);
    if (nr == TAG_LOG_MAX - 1) {
        femu_err("tag_check: further failures are counted, not logged\n");
    }
}

static void tag_check_read(struct ftl_tag *t, NvmeRequest *req, uint64_t lpn,
                           FtlTagRead *rec)
{
    uint64_t st = qatomic_read(&t->state[lpn]);
    uint32_t hi = st & TAG_VER_MASK;
    uint32_t lo = rec->lo & TAG_VER_MASK;
    bool racy = rec->racy || hi != rec->hi0;

    if (rec->lo & CP_UNTRACKED) {
        qatomic_inc(&t->skipped);
        return;
    }
    qatomic_inc(&t->checked);
    rec->racy = racy;
    if (rec->tag == FTL_TAG_UNMAPPED) {
        if ((rec->lo & CP_WRITTEN) && !(rec->lo & CP_TRIM) && !racy) {
            tag_report(t, req, lpn, rec, hi, "written page has no mapping");
        }
        return;
    }
    if (rec->tag == FTL_TAG_ERASED) {
        tag_report(t, req, lpn, rec, hi, "mapping names an erased page");
        return;
    }
    if (rec->tag >> TAG_VER_BITS != lpn) {
        tag_report(t, req, lpn, rec, hi, "mapping names another page's copy");
        return;
    }
    if (!tag_ver_between(lo, rec->tag & TAG_VER_MASK, hi)) {
        tag_report(t, req, lpn, rec, hi, "stale or unknown version");
    }
}

/*
 * @req is about to complete. A read is checked; a command that changed
 * pages moves their completed versions. Called before the completion is
 * posted, so the host never sees a write complete before a later read
 * knows to expect it.
 */
void bbssd_tag_complete(FemuCtrl *n, NvmeRequest *req)
{
    FtlTagReq *tr = req->tag;
    struct ftl_tag *t = tr->ssd->tag;

    if (tr->op == TAG_OP_READ) {
        if (req->status == NVME_SUCCESS) {
            for (uint64_t lpn = tr->ranges[0].start;
                 lpn <= tr->ranges[0].end; lpn++) {
                tag_check_read(t, req, lpn,
                               &tr->rec[lpn - tr->ranges[0].start]);
            }
        }
    } else if (tr->op == TAG_OP_WRITE) {
        for (uint64_t lpn = tr->ranges[0].start; lpn <= tr->ranges[0].end;
             lpn++) {
            if (tr->ver[lpn - tr->ranges[0].start]) {
                tag_op_end(t, lpn, req->status != NVME_SUCCESS);
            }
        }
    } else {
        for (uint32_t r = 0; r < tr->nr_ranges; r++) {
            for (uint64_t lpn = tr->ranges[r].start;
                 lpn <= tr->ranges[r].end; lpn++) {
                tag_op_end(t, lpn, req->status != NVME_SUCCESS);
            }
        }
    }
    bbssd_tag_release(req);
}

/*
 * Free what bbssd_tag_fetch() kept for @req. A command dropped without
 * completing, as a controller reset drops them, leaves its pages counted in
 * flight, and they are checked less closely from then on.
 */
void bbssd_tag_release(NvmeRequest *req)
{
    FtlTagReq *tr = req->tag;

    g_free(tr->ranges);
    g_free(tr->ver);
    g_free(tr->rec);
    g_free(tr);
    req->tag = NULL;
}

/* the totals over the controller's namespaces, for the tag-* properties */
void bbssd_tag_stats(FemuCtrl *n, uint64_t *checked, uint64_t *errors,
                     uint64_t *skipped, uint64_t *injected)
{
    *checked = *errors = *skipped = *injected = 0;
    for (uint32_t i = 0; n->namespaces && i < n->namespace_limit; i++) {
        NvmeNamespace *ns = &n->namespaces[i];
        struct ftl_tag *t;

        if (!ns->allocated || !ns->ssd || !ns->ssd->tag) {
            continue;
        }
        t = ns->ssd->tag;
        *checked += qatomic_read(&t->checked);
        *errors += qatomic_read(&t->errors);
        *skipped += qatomic_read(&t->skipped);
        *injected += qatomic_read(&t->injected);
    }
}

/*
 * With the I/O stopped, check every logical page's mapping against what the
 * I/O layer expects: a page last written maps to a page tagged with that
 * write, any other page maps to nothing, unless its last change was not
 * modelled. precond runs this on the state it built. Returns the pages found
 * wrong, logging the first.
 */
uint64_t ftl_tag_scan(struct ssd *ssd)
{
    struct ftl_tag *t = ssd->tag;
    uint64_t bad = 0;

    if (!t) {
        return 0;
    }
    for (uint64_t lpn = 0; lpn < t->nr_lpns; lpn++) {
        uint32_t cp = t->completed[lpn];
        struct ppa ppa = get_maptbl_ent(ssd, lpn);
        bool mapped = mapped_ppa(&ppa) && valid_ppa(ssd, &ppa);
        uint64_t want = lpn << TAG_VER_BITS | (cp & TAG_VER_MASK);
        uint64_t got = mapped ? t->page[ppa2pgidx(ssd, &ppa)]
                              : FTL_TAG_UNMAPPED;
        bool live = (cp & CP_WRITTEN) && !(cp & CP_TRIM);

        if (cp & CP_UNTRACKED) {
            continue;
        }
        if (live ? got == want : !mapped) {
            continue;
        }
        if (bad++ < TAG_LOG_MAX) {
            femu_err("tag_check scan: lpn %" PRIu64 " expected %s version "
                     "%u, found %s 0x%" PRIx64 "\n", lpn,
                     live ? "tag" : "no mapping", cp & TAG_VER_MASK,
                     mapped ? "tag" : "no mapping", got);
        }
    }
    qatomic_add(&t->checked, t->nr_lpns);
    qatomic_add(&t->errors, bad);
    return bad;
}

/* the arrays precond_save writes and precond_load fills */
void ftl_tag_get_arrays(struct ssd *ssd, struct ftl_tag_arrays *a)
{
    a->nr_lpns = ssd->tag->nr_lpns;
    a->page = ssd->tag->page;
    a->state = ssd->tag->state;
    a->completed = ssd->tag->completed;
}
