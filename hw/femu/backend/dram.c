#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include "../nvme.h"
#include "qemu/madvise.h"

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
    } else {
        error_setg(errp, "femu: mbe_type=%s is not one of dram, sparse, file",
                   name);
        return -1;
    }
    return 0;
}

/* CAP_IPC_LOCK lifts RLIMIT_MEMLOCK; read it without a libcap dependency */
static bool mbe_has_ipc_lock(void)
{
    g_autofree char *status = NULL;
    const char *cap, *end;
    uint64_t eff;

    if (!g_file_get_contents("/proc/self/status", &status, NULL, NULL)) {
        return false;
    }
    cap = strstr(status, "\nCapEff:");
    if (!cap || qemu_strtou64(cap + strlen("\nCapEff:"), &end, 16, &eff)) {
        return false;
    }
    return eff & (1ull << 14 /* CAP_IPC_LOCK */);
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
 */
static int mbe_pin_process(Error **errp)
{
    static bool pinned;

    if (pinned) {
        return 0;
    }
    if (mbe_check_memlock("mbe_pin_meta", errp)) {
        return -1;
    }
    if (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)) {
        error_setg_errno(errp, errno, "femu: mbe_pin_meta: mlockall failed");
        return -1;
    }
    pinned = true;
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

int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes,
                      const FemuMbeConfig *cfg, Error **errp)
{
    SsdDramBackend *b;
    int fd = -1;

    if (cfg->type == FEMU_MBE_DRAM) {
        b = *mbe = g_malloc0(sizeof(SsdDramBackend));
        b->size = nbytes;
        b->fd = -1;
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

    if (cfg->pin_meta && mbe_pin_process(errp)) {
        return -1;
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
    b->logical_space = mbe_map(nbytes, fd, errp);
    if (!b->logical_space) {
        if (fd >= 0) {
            qemu_close(fd);
        }
        g_free(b);
        return -1;
    }

    if (cfg->type == FEMU_MBE_SPARSE) {
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
                munmap(b->logical_space, nbytes);
                g_free(b);
                return -1;
            }
            b->locked = true;
        }
    }

    femu_log("backend: %" PRId64 " MiB %s backend%s%s\n", nbytes / MiB,
             cfg->type == FEMU_MBE_FILE ? "file" : "sparse",
             cfg->type == FEMU_MBE_FILE ? " on " : "",
             cfg->type == FEMU_MBE_FILE ? cfg->file : "");
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

    if (!len) {
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
 * Bytes of the backing store in host memory: for a file backend, the pages
 * of the file in the page cache. Walked in 1 GiB steps to keep the mincore
 * vector small.
 */
uint64_t backend_resident_bytes(SsdDramBackend *b)
{
    uint64_t pgsz = qemu_real_host_page_size();
    uintptr_t start, end, addr;
    uint64_t resident = 0;
    g_autofree unsigned char *vec = NULL;

    if (!b || !b->logical_space || !b->size) {
        return 0;
    }
    start = QEMU_ALIGN_DOWN((uintptr_t)b->logical_space, pgsz);
    end = ROUND_UP((uintptr_t)b->logical_space + b->size, pgsz);
    vec = g_malloc(GiB / pgsz);
    for (addr = start; addr < end; addr += GiB) {
        uint64_t len = MIN(GiB, end - addr);
        uint64_t n = len / pgsz;

        if (mincore((void *)addr, len, vec)) {
            break;
        }
        for (uint64_t i = 0; i < n; i++) {
            resident += vec[i] & 1;
        }
    }
    return resident * pgsz;
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
    if (b->logical_space && b->type != FEMU_MBE_DRAM) {
        munmap(b->logical_space, b->size);
    } else if (b->logical_space) {
        munlock(b->logical_space, b->size);
        g_free(b->logical_space);
    }
    if (b->type == FEMU_MBE_FILE && b->fd >= 0) {
        qemu_close(b->fd);
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
void backend_lock_range(SsdDramBackend *b, uint64_t off, uint64_t len)
{
    int run[2][2];
    int nr, r, i;

    if (!b || !b->range_locks || !len) {
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
