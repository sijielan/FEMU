#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include "../nvme.h"
#include "qemu/madvise.h"
#include "qemu/error-report.h"

/* Coperd: FEMU Memory Backend (mbe) for emulated SSD */

/*
 * Optionally bind the emulated-SSD backend buffer to a NUMA node before it is
 * first touched. FEMU_MBE_INTERLEAVE=<n> binds every page to node n
 * (MPOL_BIND); =on interleaves across nodes 0-1 (MPOL_INTERLEAVE). This is the
 * device-side half of the strict socket-isolation setup: pin the guest's vCPUs
 * and RAM to one socket and the FEMU poller threads + this backend to the
 * other, so the only thing crossing the inter-socket link is the per-I/O
 * emulation copy and the two DRAM-bandwidth domains do not contend. A direct
 * mbind(2) syscall avoids a libnuma build dependency. No-op (default) when the
 * env var is unset, so existing single-socket setups are unchanged.
 */
static void mbe_numa_bind(void *addr, int64_t len)
{
    const char *il = getenv("FEMU_MBE_INTERLEAVE");
    if (!il || !il[0]) {
        return;
    }
    if (strcmp(il, "on") && strcmp(il, "0") && strcmp(il, "1")) {
        femu_err("backend: ignoring FEMU_MBE_INTERLEAVE=%s (want on|0|1)\n", il);
        return;
    }
    int mode = strcmp(il, "on") ? 2 /* MPOL_BIND */ : 3 /* MPOL_INTERLEAVE */;
    unsigned long nodemask = strcmp(il, "on") ? (1ul << atoi(il)) : 0x3ul;

    /*
     * mbind(2) requires a page-aligned start address; g_malloc0 returns only
     * malloc alignment. Round the start down and the length up to whole pages
     * so the policy covers every page backing the buffer. (Touching the shared
     * boundary pages is harmless: the policy only steers where not-yet-faulted
     * pages land, and the prealloc below faults our buffer immediately.)
     */
    long pgsz = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)pgsz - 1);
    uintptr_t end = ((uintptr_t)addr + len + pgsz - 1) & ~((uintptr_t)pgsz - 1);
    /*
     * MPOL_MF_MOVE (0x2): g_malloc0 has already zeroed (hence faulted) the
     * pages onto the default node, so a plain mbind would not relocate them.
     * MF_MOVE migrates the already-resident pages to the target node now.
     */
    if (syscall(SYS_mbind, (void *)start, end - start, mode, &nodemask,
                sizeof(nodemask) * 8, 0x2 /* MPOL_MF_MOVE */)) {
        femu_err("backend: mbind(FEMU_MBE_INTERLEAVE=%s) failed: %s\n",
                 il, strerror(errno));
    } else {
        femu_log("backend: %ld MB bound via FEMU_MBE_INTERLEAVE=%s\n",
                 (long)(len >> 20), il);
    }
}

int femu_mbe_parse_type(const char *name, FemuMbeType *type, Error **errp)
{
    if (!name || !strcmp(name, "dram")) {
        *type = FEMU_MBE_DRAM;
    } else if (!strcmp(name, "sparse")) {
        *type = FEMU_MBE_SPARSE;
    } else if (!strcmp(name, "file")) {
        *type = FEMU_MBE_FILE;
    } else if (!strcmp(name, "none")) {
        *type = FEMU_MBE_NONE;
    } else {
        error_setg(errp, "femu: mbe_type=%s is not one of dram, sparse, file, "
                   "none", name);
        return -1;
    }
    return 0;
}

#define MBE_CAP_IPC_LOCK (1ull << 14)

/* one capability set of this process; read without a libcap dependency */
static uint64_t mbe_cap_set(const char *field)
{
    g_autofree char *status = NULL;
    g_autofree char *key = g_strdup_printf("\n%s:", field);
    const char *cap, *end;
    uint64_t set;

    if (!g_file_get_contents("/proc/self/status", &status, NULL, NULL)) {
        return 0;
    }
    cap = strstr(status, key);
    if (!cap || qemu_strtou64(cap + strlen(key), &end, 16, &set)) {
        return 0;
    }
    return set;
}

/* CAP_IPC_LOCK lifts RLIMIT_MEMLOCK */
static bool mbe_has_ipc_lock(void)
{
    return mbe_cap_set("CapEff") & MBE_CAP_IPC_LOCK;
}

/*
 * A binary given CAP_IPC_LOCK with setcap, the way to pin without a raised
 * memlock limit, runs non-dumpable, which makes /proc/self/pagemap root's
 * and unreadable to the process itself: a sparse backend could no longer
 * count its resident and swapped pages, nor tools the user runs read its
 * smaps. When the process holds no other capability and is not set-id,
 * being dumpable exposes nothing: the same user may run the binary and get
 * the same capability anyway. Then make it dumpable again; leave every
 * other case as the kernel set it.
 */
static void mbe_restore_dumpable(void)
{
    if (prctl(PR_GET_DUMPABLE) == 1 ||
        mbe_cap_set("CapPrm") != MBE_CAP_IPC_LOCK ||
        getuid() != geteuid() || getgid() != getegid()) {
        return;
    }
    if (prctl(PR_SET_DUMPABLE, 1)) {
        warn_report("femu: cannot make QEMU dumpable again after setcap "
                    "(%s): a sparse backend counts its pages with mincore()",
                    strerror(errno));
    }
}

/* Locking more than the limit fails, now or at some later allocation. */
static int mbe_check_memlock(const char *what, Error **errp)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_MEMLOCK, &rl) || rl.rlim_cur == RLIM_INFINITY ||
        mbe_has_ipc_lock()) {
        return 0;
    }
    error_setg(errp, "femu: %s needs RLIMIT_MEMLOCK unlimited (it is %" PRIu64
               " bytes) or CAP_IPC_LOCK; run as root or under ulimit -l "
               "unlimited", what, (uint64_t)rl.rlim_cur);
    return -1;
}

/*
 * When the host may reclaim the data of a sparse or file backend, it may
 * reclaim anything else in the process too, and an FTL thread or poller that
 * faults on its metadata, a ring or its stack stalls with the emulated clock
 * running. So pin every page of the process, now and later, and leave only
 * the backends' data reclaimable: each is unlocked as it is mapped, after
 * this. MCL_ONFAULT pins a page when it is first touched, not at once, which
 * would fault in all of guest memory and every mapping made later. Once per
 * process, since a second MCL_CURRENT would pin the data mapped since.
 *
 * Pinning needs RLIMIT_MEMLOCK unlimited or CAP_IPC_LOCK, which a user
 * rarely has. With mbe_pin_meta=auto, the default, a process that cannot
 * pin says what that costs and runs unpinned, as FEMU does when it cannot
 * pin a dram backend: the data stays right, only faults on the metadata may
 * show up as late completions. mbe_pin_meta=on refuses to run unpinned.
 */
static int mbe_pin_process(OnOffAuto mode, Error **errp)
{
    static bool pinned, warned;
    Error *err = NULL;

    if (pinned || mode == ON_OFF_AUTO_OFF) {
        return 0;
    }
    if (!mbe_check_memlock("mbe_pin_meta", &err)) {
        if (!mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) {
            pinned = true;
            return 0;
        }
        error_setg_errno(&err, errno, "femu: mbe_pin_meta: mlockall failed");
    }
    if (mode == ON_OFF_AUTO_ON) {
        error_propagate(errp, err);
        return -1;
    }
    if (!warned) {
        warn_report_err(err);
        warn_report("femu: running with FTL metadata and FEMU threads "
                    "unpinned: if the host pages them out, the faults show "
                    "up as late completions. Raise the memlock limit "
                    "(limits.conf memlock unlimited, or setcap cap_ipc_lock) "
                    "to pin them, or set mbe_pin_meta=off to silence this");
        warned = true;
    } else {
        error_free(err);
    }
    return 0;
}

/*
 * Map the data with none of it resident. The mapping starts PROT_NONE, which
 * neither mlockall(MCL_FUTURE) nor -overcommit mem-lock=on populates, is
 * unlocked, and only then made accessible, so a page takes host memory when
 * the guest first writes it and the host may reclaim it afterwards.
 */
static void *mbe_map(int64_t len, int fd, Error **errp)
{
    int flags = fd < 0 ? MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE
                       : MAP_SHARED;
    void *p = mmap(NULL, len, PROT_NONE, flags, fd, 0);

    if (p == MAP_FAILED) {
        error_setg_errno(errp, errno, "femu: cannot map the %" PRId64
                         " MiB memory backend", len / MiB);
        return NULL;
    }
    munlock(p, len);
    if (mprotect(p, len, PROT_READ | PROT_WRITE)) {
        error_setg_errno(errp, errno, "femu: cannot map the %" PRId64
                         " MiB memory backend", len / MiB);
        munmap(p, len);
        return NULL;
    }
    return p;
}

/*
 * Open the file a file backend maps, sized to the backend. A shorter file is
 * extended with a hole; a longer one is refused rather than cut. The file
 * system has to have room for the blocks not yet allocated: a write fault on
 * a hole it cannot fill raises SIGBUS and takes QEMU down mid-run.
 */
static int mbe_open_file(const char *path, int64_t len, Error **errp)
{
    struct statvfs vfs;
    struct stat st;
    uint64_t need;
    int fd;

    fd = qemu_create(path, O_RDWR, 0644, errp);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st)) {
        error_setg_errno(errp, errno, "femu: mbe_file %s", path);
        goto fail;
    }
    if (!S_ISREG(st.st_mode)) {
        error_setg(errp, "femu: mbe_file %s is not a regular file", path);
        goto fail;
    }
    if (st.st_size > len) {
        error_setg(errp, "femu: mbe_file %s holds %" PRId64 " bytes, more "
                   "than the %" PRId64 " byte backend; remove or truncate it",
                   path, (int64_t)st.st_size, len);
        goto fail;
    }
    need = len - MIN((uint64_t)st.st_blocks * 512, (uint64_t)len);
    if (fstatvfs(fd, &vfs)) {
        error_setg_errno(errp, errno, "femu: mbe_file %s", path);
        goto fail;
    }
    if ((uint64_t)vfs.f_bavail * vfs.f_frsize < need) {
        error_setg(errp, "femu: mbe_file %s needs %" PRIu64 " MiB more free "
                   "space than its file system has (%" PRIu64 " MiB)", path,
                   need / MiB, (uint64_t)vfs.f_bavail * vfs.f_frsize / MiB);
        goto fail;
    }
    if (st.st_size < len && ftruncate(fd, len)) {
        error_setg_errno(errp, errno, "femu: cannot size mbe_file %s", path);
        goto fail;
    }
    return fd;

fail:
    qemu_close(fd);
    return -1;
}

/* How often the eviction thread compares the backend with its budget. */
#define BACKEND_EVICT_MS        100
/* Periods it takes to recount every chunk once, whether used or not. */
#define BACKEND_EVICT_SWEEP     600

static bool mbe_host_has_swap(void)
{
    g_autofree char *info = NULL;
    const char *swap, *end;
    uint64_t kb;

    if (!g_file_get_contents("/proc/meminfo", &info, NULL, NULL)) {
        return false;
    }
    swap = strstr(info, "\nSwapTotal:");
    return swap && !qemu_strtou64(swap + strlen("\nSwapTotal:"), &end, 10,
                                  &kb) && kb;
}

static uint64_t backend_chunk_len(SsdDramBackend *b, uint64_t c)
{
    uint64_t off = c << BACKEND_CHUNK_SHIFT;

    return MIN((uint64_t)1 << BACKEND_CHUNK_SHIFT, (uint64_t)b->size - off);
}

/*
 * Resident pages of [addr, addr + len), page aligned, counted @cap pages at a
 * time into @buf (cap * 8 bytes). mincore() would do for file data but not
 * for sparse data: a page MADV_PAGEOUT has written to swap stays in the swap
 * cache, which mincore() reports as resident although the process no longer
 * maps it. So sparse data is counted from /proc/self/pagemap, as pages
 * present and mapped by this process alone, which also leaves out the
 * shared zero page a read of a block never written maps in.
 */
static uint64_t backend_count_pages(SsdDramBackend *b, uintptr_t addr,
                                    uint64_t len, void *buf, uint64_t cap)
{
    uint64_t pgsz = qemu_real_host_page_size();
    uint64_t pages = 0;

    while (len) {
        uint64_t n = MIN(len / pgsz, cap);

        if (b->pagemap_fd >= 0) {
            uint64_t *pm = buf;
            ssize_t got = pread(b->pagemap_fd, pm, n * sizeof(*pm),
                                addr / pgsz * sizeof(*pm));

            if (got != n * sizeof(*pm)) {
                break;
            }
            for (uint64_t i = 0; i < n; i++) {
                pages += (pm[i] >> 63) & (pm[i] >> 56) & 1;
            }
        } else {
            unsigned char *vec = buf;

            if (mincore((void *)addr, n * pgsz, vec)) {
                break;
            }
            for (uint64_t i = 0; i < n; i++) {
                pages += vec[i] & 1;
            }
        }
        addr += n * pgsz;
        len -= n * pgsz;
    }
    return pages;
}

/* Resident pages of chunk @c. The backend is page aligned, being mmap'd. */
static uint16_t backend_count_chunk(SsdDramBackend *b, uint64_t c)
{
    uint64_t pgsz = qemu_real_host_page_size();
    uint64_t buf[((uint64_t)1 << BACKEND_CHUNK_SHIFT) / 4096];

    return backend_count_pages(b, (uintptr_t)b->logical_space +
                               (c << BACKEND_CHUNK_SHIFT),
                               ROUND_UP(backend_chunk_len(b, c), pgsz), buf,
                               ARRAY_SIZE(buf));
}

/*
 * Take chunk @c out of host memory. Sparse data goes to swap, where zswap
 * may keep it compressed; MADV_PAGEOUT never drops it. File data is written
 * back, unmapped from the process and then dropped from the page cache; a
 * page the guest writes again meanwhile is dirty and stays. Nothing here
 * loses data, so a poller may touch the chunk at any point and simply
 * faults it back in.
 */
static void backend_evict_chunk(SsdDramBackend *b, uint64_t c)
{
    uint64_t off = c << BACKEND_CHUNK_SHIFT;
    uint64_t len = backend_chunk_len(b, c);
    uint8_t *addr = (uint8_t *)b->logical_space + off;

    if (b->type == FEMU_MBE_SPARSE) {
        madvise(addr, len, MADV_PAGEOUT);
        return;
    }
    msync(addr, len, MS_SYNC);
    qemu_madvise(addr, len, QEMU_MADV_DONTNEED);
    posix_fadvise(b->fd, off, len, POSIX_FADV_DONTNEED);
}

/*
 * Keep the backend's resident data within mbe_budget_mb from a thread of
 * its own, so a poller rarely meets reclaim in a page fault; a cgroup memory
 * limit then serves only as the last resort. Counting every page of a large
 * backend takes the better part of a second, so the thread counts only the
 * chunks used since it last looked, plus a slice of all of them that
 * catches what the kernel reclaimed on its own. When over budget it evicts
 * chunks by CLOCK, passing over those used since the hand last came by,
 * until it is 1/16 below the budget.
 */
static void *backend_evict_thread(void *opaque)
{
    SsdDramBackend *b = opaque;
    uint64_t pgsz = qemu_real_host_page_size();
    uint64_t slice = DIV_ROUND_UP(b->nr_chunks, BACKEND_EVICT_SWEEP);
    uint64_t target = b->budget - b->budget / 16;
    uint64_t resident = 0;
    uint64_t sweep = 0;
    uint64_t hand = 0;

    rcu_register_thread();
    /* behind the pollers and FTL threads when they share a CPU */
    if (setpriority(PRIO_PROCESS, qemu_get_thread_id(), 10)) {
        femu_err("backend: cannot lower the eviction thread's priority\n");
    }
    while (!qatomic_read(&b->evict_stop)) {
        for (uint64_t c = 0; c < b->nr_chunks; c++) {
            bool sweeping = c - sweep < slice;

            if (!(qatomic_read(&b->chunk_flags[c]) & BACKEND_CHUNK_SEEN) &&
                !sweeping) {
                continue;
            }
            qatomic_fetch_and(&b->chunk_flags[c], ~BACKEND_CHUNK_SEEN);
            resident -= (uint64_t)b->chunk_pages[c] * pgsz;
            b->chunk_pages[c] = backend_count_chunk(b, c);
            resident += (uint64_t)b->chunk_pages[c] * pgsz;
        }
        sweep = sweep + slice >= b->nr_chunks ? 0 : sweep + slice;

        for (uint64_t scanned = 0; resident > target &&
             scanned < 2 * b->nr_chunks && !qatomic_read(&b->evict_stop);
             scanned++) {
            uint64_t c = hand;
            uint16_t left;

            hand = hand + 1 == b->nr_chunks ? 0 : hand + 1;
            if (qatomic_fetch_and(&b->chunk_flags[c], ~BACKEND_CHUNK_REF) &
                BACKEND_CHUNK_REF) {
                continue;
            }
            if (!b->chunk_pages[c]) {
                continue;
            }
            backend_evict_chunk(b, c);
            left = backend_count_chunk(b, c);
            if (left < b->chunk_pages[c]) {
                qatomic_add(&b->evicted,
                            (uint64_t)(b->chunk_pages[c] - left) * pgsz);
            }
            resident -= (uint64_t)b->chunk_pages[c] * pgsz;
            resident += (uint64_t)left * pgsz;
            b->chunk_pages[c] = left;
        }
        qemu_sem_timedwait(&b->evict_sem, BACKEND_EVICT_MS);
    }
    rcu_unregister_thread();
    return NULL;
}

static int backend_start_eviction(SsdDramBackend *b, uint64_t budget,
                                  Error **errp)
{
    if (b->type == FEMU_MBE_SPARSE && !mbe_host_has_swap()) {
        error_setg(errp, "femu: mbe_budget_mb with mbe_type=sparse evicts to "
                   "swap, and the host has none; add swap (zswap keeps it "
                   "compressed in memory) or use mbe_type=file");
        return -1;
    }
    b->budget = budget;
    b->nr_chunks = DIV_ROUND_UP(b->size, (uint64_t)1 << BACKEND_CHUNK_SHIFT);
    b->chunk_flags = g_new0(uint8_t, b->nr_chunks);
    b->chunk_pages = g_new0(uint16_t, b->nr_chunks);
    qemu_sem_init(&b->evict_sem, 0);
    qemu_thread_create(&b->evict_thread, "femu-mbe-evict",
                       backend_evict_thread, b, QEMU_THREAD_JOINABLE);
    return 0;
}

static void backend_stop_eviction(SsdDramBackend *b)
{
    if (!b->budget) {
        return;
    }
    qatomic_set(&b->evict_stop, true);
    qemu_sem_post(&b->evict_sem);
    qemu_thread_join(&b->evict_thread);
    qemu_sem_destroy(&b->evict_sem);
    g_free(b->chunk_flags);
    g_free(b->chunk_pages);
    b->chunk_flags = NULL;
    b->chunk_pages = NULL;
    b->budget = 0;
}

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes,
                      const FemuMbeConfig *cfg, Error **errp)
{
    SsdDramBackend *b;
    int fd = -1;

    if (cfg->type == FEMU_MBE_DRAM) {
        b = *mbe = g_malloc0(sizeof(SsdDramBackend));
        b->size = nbytes;
        b->fd = -1;
        b->pagemap_fd = -1;
        b->logical_space = g_malloc0(nbytes);

        /* bind to the requested NUMA node before mlock faults the pages in */
        mbe_numa_bind(b->logical_space, nbytes);

        /*
         * Pinning keeps page faults out of the emulated latency, but it needs
         * RLIMIT_MEMLOCK to cover the backend, which an unprivileged run
         * rarely has. Say what that costs and carry on rather than refuse to
         * start: the device works either way, only its timing is then subject
         * to faults.
         */
        if (mlock(b->logical_space, nbytes) == -1) {
            femu_err("cannot pin the %" PRId64 " MiB memory backend (%s); "
                     "latencies may jitter until RLIMIT_MEMLOCK allows it\n",
                     nbytes / MiB, strerror(errno));
        }

        backend_init_range_locks(b);
        return 0;
    }

    mbe_restore_dumpable();
    if (mbe_pin_process(cfg->pin_meta, errp)) {
        return -1;
    }
    if (cfg->type == FEMU_MBE_NONE) {
        b = *mbe = g_malloc0(sizeof(SsdDramBackend));
        b->size = nbytes;
        b->type = FEMU_MBE_NONE;
        b->fd = -1;
        b->pagemap_fd = -1;
        femu_log("backend: %" PRId64 " MiB, no data kept (mbe_type=none)\n",
                 nbytes / MiB);
        backend_init_range_locks(b);
        return 0;
    }
    if (cfg->lock && mbe_check_memlock("mbe_lock", errp)) {
        return -1;
    }
    if (cfg->type == FEMU_MBE_FILE) {
        fd = mbe_open_file(cfg->file, nbytes, errp);
        if (fd < 0) {
            return -1;
        }
    }

    b = g_malloc0(sizeof(SsdDramBackend));
    b->size = nbytes;
    b->type = cfg->type;
    b->fd = fd;
    b->pagemap_fd = -1;
    b->prefetch = cfg->prefetch;
    b->logical_space = mbe_map(nbytes, fd, errp);
    if (!b->logical_space) {
        if (fd >= 0) {
            qemu_close(fd);
        }
        g_free(b);
        return -1;
    }

    if (cfg->type == FEMU_MBE_SPARSE) {
        /* see backend_count_pages(); without it, fall back to mincore() */
        b->pagemap_fd = qemu_open_old("/proc/self/pagemap", O_RDONLY);
        /*
         * A huge page takes 2 MiB for a 4 KiB write, and a deallocate of part
         * of one splits it rather than frees it, so the default keeps the
         * backend to base pages whatever the host's THP setting.
         */
        qemu_madvise(b->logical_space, nbytes,
                     cfg->thp ? QEMU_MADV_HUGEPAGE : QEMU_MADV_NOHUGEPAGE);
        mbe_numa_bind(b->logical_space, nbytes);
        if (cfg->lock) {
            if (mlock2(b->logical_space, nbytes, MLOCK_ONFAULT)) {
                error_setg_errno(errp, errno, "femu: mbe_lock: mlock2 failed");
                free_dram_backend(b);
                return -1;
            }
            b->locked = true;
        }
    }

    if (cfg->budget && backend_start_eviction(b, cfg->budget, errp)) {
        free_dram_backend(b);
        return -1;
    }

    femu_log("backend: %" PRId64 " MiB %s backend%s%s, budget %" PRIu64
             " MiB\n", nbytes / MiB,
             cfg->type == FEMU_MBE_FILE ? "file" : "sparse",
             cfg->type == FEMU_MBE_FILE ? " on " : "",
             cfg->type == FEMU_MBE_FILE ? cfg->file : "", cfg->budget / MiB);
    *mbe = b;
    backend_init_range_locks(b);

    return 0;
}

/*
 * Zero [off, off + len) of the backing store. A sparse backend gives the
 * whole pages back to the host, which then read as zero, and a file backend
 * punches them out of the file, so a deallocate takes memory away rather
 * than faulting in every page it clears. Bytes that cannot be dropped are
 * written. The caller keeps other accesses to the range out.
 */
void backend_zero_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    uint8_t *base = b->logical_space;
    uint64_t pgsz = qemu_real_host_page_size();
    uint64_t start = ROUND_UP(off, pgsz);
    uint64_t end = QEMU_ALIGN_DOWN(off + len, pgsz);

    if (!len || b->type == FEMU_MBE_NONE) {
        return;
    }
    if (b->type == FEMU_MBE_FILE &&
        !fallocate(b->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off,
                   len)) {
        return;
    }
    if (b->type == FEMU_MBE_SPARSE && start < end) {
        bool dropped;

        /* MADV_DONTNEED refuses locked pages */
        if (b->locked) {
            munlock(base + start, end - start);
        }
        dropped = !qemu_madvise(base + start, end - start,
                                QEMU_MADV_DONTNEED);
        if (b->locked) {
            mlock2(base + start, end - start, MLOCK_ONFAULT);
        }
        if (dropped) {
            memset(base + off, 0, start - off);
            memset(base + end, 0, off + len - end);
            return;
        }
    }
    memset(base + off, 0, len);
}

/*
 * Ask the host to bring [off, off + len) into memory without waiting for it:
 * a file backend starts reading the range from the file, a sparse one
 * starts reading it back from swap. Out-of-range requests are ignored; this
 * is a hint, and the access that follows checks the range itself.
 */
void backend_prefetch(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    uint64_t pgsz = qemu_real_host_page_size();
    uint64_t start, end;

    if (!b->logical_space || !len || off > (uint64_t)b->size ||
        len > (uint64_t)b->size - off) {
        return;
    }
    start = QEMU_ALIGN_DOWN(off, pgsz);
    end = ROUND_UP(off + len, pgsz);
    qemu_madvise((uint8_t *)b->logical_space + start, end - start,
                 QEMU_MADV_WILLNEED);
}

/*
 * Bytes of the backing store in host memory: for a file backend, the pages
 * of the file in the page cache. A walk of a backend of some TiB takes the
 * better part of a second.
 */
uint64_t backend_resident_bytes(SsdDramBackend *b)
{
    const uint64_t cap = 64 * KiB;
    uint64_t pgsz = qemu_real_host_page_size();
    g_autofree uint64_t *buf = NULL;
    uintptr_t start, end;

    if (!b || !b->logical_space || !b->size) {
        return 0;
    }
    start = QEMU_ALIGN_DOWN((uintptr_t)b->logical_space, pgsz);
    end = ROUND_UP((uintptr_t)b->logical_space + b->size, pgsz);
    buf = g_new(uint64_t, cap);
    return backend_count_pages(b, start, end - start, buf, cap) * pgsz;
}

/*
 * Bytes of a sparse backend's data the host has swapped out, to zswap or to
 * a swap device: pages /proc/self/pagemap reports swapped (bit 62). Other
 * types have no anonymous data to swap.
 */
uint64_t backend_swapped_bytes(SsdDramBackend *b)
{
    const uint64_t cap = 64 * KiB;
    uint64_t pgsz = qemu_real_host_page_size();
    g_autofree uint64_t *pm = NULL;
    uintptr_t addr, end;
    uint64_t swapped = 0;

    if (!b || b->pagemap_fd < 0 || !b->logical_space) {
        return 0;
    }
    addr = (uintptr_t)b->logical_space;
    end = addr + ROUND_UP(b->size, pgsz);
    pm = g_new(uint64_t, cap);
    while (addr < end) {
        uint64_t n = MIN((end - addr) / pgsz, cap);

        if (pread(b->pagemap_fd, pm, n * sizeof(*pm),
                  addr / pgsz * sizeof(*pm)) != n * sizeof(*pm)) {
            break;
        }
        for (uint64_t i = 0; i < n; i++) {
            swapped += (pm[i] >> 62) & 1;
        }
        addr += n * pgsz;
    }
    return swapped * pgsz;
}

/*
 * The zswap pool of this process's memory cgroup: @pool bytes holding
 * @stored bytes of compressed pages, from memory.stat. With mbe_pin_meta
 * everything but the backend data is locked, so that is what zswap holds.
 * Both 0 when the cgroup or the fields are not there.
 */
void backend_cgroup_zswap(uint64_t *pool, uint64_t *stored)
{
    g_autofree char *cg = NULL;
    g_autofree char *path = NULL;
    g_autofree char *stat = NULL;
    const char *p;

    *pool = *stored = 0;
    if (!g_file_get_contents("/proc/self/cgroup", &cg, NULL, NULL) ||
        !(p = strstr(cg, "0::"))) {
        return;
    }
    path = g_strdup_printf("/sys/fs/cgroup%.*s/memory.stat",
                           (int)strcspn(p + 3, "\n"), p + 3);
    if (!g_file_get_contents(path, &stat, NULL, NULL)) {
        return;
    }
    for (p = stat; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        const char *end;

        if (strstart(p, "zswap ", NULL)) {
            qemu_strtou64(p + 6, &end, 10, pool);
        } else if (strstart(p, "zswapped ", NULL)) {
            qemu_strtou64(p + 9, &end, 10, stored);
        }
    }
}

/* A backend another device lends takes its locks from the borrower. */
void backend_init_range_locks(SsdDramBackend *b)
{
    if (b->range_locks) {
        return;
    }
    b->range_locks = g_new(QemuMutex, BACKEND_RANGE_LOCKS);
    for (int i = 0; i < BACKEND_RANGE_LOCKS; i++) {
        qemu_mutex_init(&b->range_locks[i]);
    }
}

void backend_free_range_locks(SsdDramBackend *b)
{
    if (!b || !b->range_locks) {
        return;
    }
    for (int i = 0; i < BACKEND_RANGE_LOCKS; i++) {
        qemu_mutex_destroy(&b->range_locks[i]);
    }
    g_free(b->range_locks);
    b->range_locks = NULL;
}

void free_dram_backend(SsdDramBackend *b)
{
    if (!b) {
        return;
    }
    backend_stop_eviction(b);
    if (b->logical_space && b->type != FEMU_MBE_DRAM) {
        munmap(b->logical_space, b->size);
    } else if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
    }
    if (b->type == FEMU_MBE_FILE && b->fd >= 0) {
        qemu_close(b->fd);
    }
    if (b->type == FEMU_MBE_SPARSE && b->pagemap_fd >= 0) {
        qemu_close(b->pagemap_fd);
    }
    backend_free_range_locks(b);
    g_free(b);
}

/*
 * The locks of [off, off + len) as one or two runs of lock indexes, lowest
 * first. Every access takes its locks in index order, so two accesses never
 * wait on each other in a cycle.
 */
static int backend_range_runs(uint64_t off, uint64_t len, int run[2][2])
{
    uint64_t g0 = off >> BACKEND_RANGE_SHIFT;
    uint64_t g1 = (off + len - 1) >> BACKEND_RANGE_SHIFT;
    int s0 = g0 % BACKEND_RANGE_LOCKS;
    int s1 = g1 % BACKEND_RANGE_LOCKS;

    if (g1 - g0 >= BACKEND_RANGE_LOCKS - 1) {
        run[0][0] = 0;
        run[0][1] = BACKEND_RANGE_LOCKS - 1;
        return 1;
    }
    if (s0 <= s1) {
        run[0][0] = s0;
        run[0][1] = s1;
        return 1;
    }
    run[0][0] = 0;
    run[0][1] = s1;
    run[1][0] = s0;
    run[1][1] = BACKEND_RANGE_LOCKS - 1;
    return 2;
}

/*
 * Make an access to [off, off + len) of the backing store atomic with
 * respect to every other access that takes the locks of its range.
 */
/* Tell the eviction thread that [off, off + len) is in use. */
static inline void backend_mark_chunks(SsdDramBackend *b, uint64_t off,
                                       uint64_t len)
{
    uint64_t c = off >> BACKEND_CHUNK_SHIFT;
    uint64_t last = MIN((off + len - 1) >> BACKEND_CHUNK_SHIFT,
                        b->nr_chunks - 1);
    const uint8_t all = BACKEND_CHUNK_REF | BACKEND_CHUNK_SEEN;

    for (; c <= last; c++) {
        /* a store only on change keeps pollers off each other's lines */
        if (qatomic_read(&b->chunk_flags[c]) != all) {
            qatomic_set(&b->chunk_flags[c], all);
        }
    }
}

void backend_lock_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    int run[2][2];
    int nr, r, i;

    if (!b || !len) {
        return;
    }
    if (b->chunk_flags) {
        backend_mark_chunks(b, off, len);
    }
    if (!b->range_locks) {
        return;
    }
    nr = backend_range_runs(off, len, run);
    for (r = 0; r < nr; r++) {
        for (i = run[r][0]; i <= run[r][1]; i++) {
            if (qemu_mutex_trylock(&b->range_locks[i])) {
                qatomic_inc(&b->range_waits);
                qemu_mutex_lock(&b->range_locks[i]);
            }
        }
    }
}

void backend_unlock_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    int run[2][2];
    int nr, r, i;

    if (!b || !b->range_locks || !len) {
        return;
    }
    nr = backend_range_runs(off, len, run);
    for (r = 0; r < nr; r++) {
        for (i = run[r][0]; i <= run[r][1]; i++) {
            qemu_mutex_unlock(&b->range_locks[i]);
        }
    }
}

/*
 * qtest only: stop a write halfway through its copy while x-copy-hold is set,
 * at most 60 s, and show the stop in x-copy-held. A read sent meanwhile meets
 * a half-written block unless the range locks keep it out.
 */
void femu_test_copy_hold(FemuCtrl *n)
{
    int ms;

    qatomic_store_release(&n->test_copy_held, 1);
    for (ms = 0; ms < 60000 && qatomic_load_acquire(&n->test_copy_hold);
         ms++) {
        g_usleep(1000);
    }
    qatomic_store_release(&n->test_copy_held, 0);
}

/* One guest transfer; a write split in two when a qtest asks for it. */
static MemTxResult backend_copy(FemuCtrl *n, dma_addr_t addr, void *ptr,
                                dma_addr_t len, bool to_host)
{
    dma_addr_t half = len / 2;

    if (likely(!qatomic_read(&n->test_copy_hold)) || to_host || !half) {
        return femu_dma_rw(n, addr, ptr, len, to_host);
    }
    if (femu_dma_rw(n, addr, ptr, half, false)) {
        return MEMTX_ERROR;
    }
    femu_test_copy_hold(n);
    return femu_dma_rw(n, addr + half, (uint8_t *)ptr + half, len - half,
                       false);
}

/*
 * A backend with no data: a read gets zeros, a write is dropped. The offsets
 * are checked as backend_rw() checks them, so a mode's bad translation fails
 * the same way whatever the backend.
 */
static int backend_rw_nodata(SsdDramBackend *b, QEMUSGList *qsg,
                             uint64_t *lbal, bool is_write)
{
    static const uint8_t zeros[64 * KiB];
    FemuCtrl *n = container_of(qsg->dev, FemuCtrl, parent_obj.qdev);
    bool per_entry = b->femu_mode == FEMU_OCSSD_MODE;
    uint64_t mb_oft = lbal[0];
    int ret = 0;

    for (int i = 0; i < qsg->nsg && !ret; i++) {
        dma_addr_t addr = qsg->sg[i].base;
        dma_addr_t len = qsg->sg[i].len;

        if (per_entry) {
            mb_oft = lbal[i];
        }
        if (mb_oft > (uint64_t)b->size || len > (uint64_t)b->size - mb_oft) {
            femu_err("backend: %" PRIu64 "+%" PRIu64 " is outside the %" PRId64
                     " byte backing store\n", mb_oft, (uint64_t)len, b->size);
            ret = -ERANGE;
            break;
        }
        while (!is_write && len) {
            dma_addr_t step = MIN(len, sizeof(zeros));

            if (femu_dma_rw(n, addr, (void *)zeros, step, true)) {
                ret = -EIO;
                break;
            }
            addr += step;
            len -= step;
        }
        mb_oft += qsg->sg[i].len;
    }
    qemu_sglist_destroy(qsg);
    return ret;
}

/*
 * Copy between guest memory and the backing store. The scatter list is
 * consumed whatever the outcome. Returns 0, -ERANGE when a mode's address
 * translation leaves the backing store, or -EIO when guest memory could not
 * be reached.
 */
int backend_rw(SsdDramBackend *b, QEMUSGList *qsg, uint64_t *lbal, bool is_write)
{
    int sg_cur_index = 0;
    dma_addr_t sg_cur_byte = 0;
    dma_addr_t cur_addr, cur_len;
    uint64_t mb_oft = lbal[0];
    void *mb = b->logical_space;

    DMADirection dir = DMA_DIRECTION_FROM_DEVICE;
    /* OCSSD takes one offset per entry; every other mode, one range */
    bool per_entry = b->femu_mode == FEMU_OCSSD_MODE;
    uint64_t lock_oft = mb_oft;
    uint64_t lock_len = qsg->size;
    int ret = 0;

    if (b->type == FEMU_MBE_NONE) {
        return backend_rw_nodata(b, qsg, lbal, is_write);
    }
    if (is_write) {
        dir = DMA_DIRECTION_TO_DEVICE;
    }

    if (!per_entry) {
        backend_lock_range(b, lock_oft, lock_len);
    }
    while (sg_cur_index < qsg->nsg) {
        cur_addr = qsg->sg[sg_cur_index].base + sg_cur_byte;
        cur_len = qsg->sg[sg_cur_index].len - sg_cur_byte;
        /*
         * The offset comes from a mode's own address translation. Refuse one
         * that leaves the backing store rather than reading or writing past it,
         * which corrupts the heap and takes QEMU down with it.
         */
        if (mb_oft > (uint64_t)b->size ||
            cur_len > (uint64_t)b->size - mb_oft) {
            femu_err("backend: %" PRIu64 "+%" PRIu64 " is outside the %" PRId64
                     " byte backing store\n", (uint64_t)mb_oft,
                     (uint64_t)cur_len, b->size);
            ret = -ERANGE;
            break;
        }
        if (per_entry) {
            backend_lock_range(b, mb_oft, cur_len);
        }
        if (backend_copy(container_of(qsg->dev, FemuCtrl, parent_obj.qdev),
                         cur_addr, mb + mb_oft, cur_len,
                         dir == DMA_DIRECTION_FROM_DEVICE)) {
            ret = -EIO;
        }
        if (per_entry) {
            backend_unlock_range(b, mb_oft, cur_len);
        }
        if (ret) {
            break;
        }

        sg_cur_byte += cur_len;
        if (sg_cur_byte == qsg->sg[sg_cur_index].len) {
            sg_cur_byte = 0;
            ++sg_cur_index;
        }

        if (b->femu_mode == FEMU_OCSSD_MODE) {
            /*
             * One offset per scatter-gather entry. Reading the next one after
             * the index has passed the last entry reads one element off the
             * end of the list: the value went unused, but the read did not.
             */
            if (sg_cur_index < qsg->nsg) {
                mb_oft = lbal[sg_cur_index];
            }
        } else if (b->femu_mode == FEMU_BBSSD_MODE ||
                   b->femu_mode == FEMU_NOSSD_MODE ||
                   b->femu_mode == FEMU_ZNSSD_MODE ||
                   b->femu_mode == FEMU_CSD_MODE ||
                   b->femu_mode == FEMU_KVSSD_MODE) {
            mb_oft += cur_len;
        } else {
            assert(0);
        }
    }

    if (!per_entry) {
        backend_unlock_range(b, lock_oft, lock_len);
    }
    qemu_sglist_destroy(qsg);

    return ret;
}
