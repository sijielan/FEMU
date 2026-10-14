#ifndef __FEMU_MEM_BACKEND
#define __FEMU_MEM_BACKEND

#include <stdint.h>

/*
 * Pollers copy data in parallel, so an access holds the locks of the 4 KiB
 * granules it touches. Granules share BACKEND_RANGE_LOCKS locks, granule g
 * taking lock g % BACKEND_RANGE_LOCKS.
 */
#define BACKEND_RANGE_SHIFT     12
#define BACKEND_RANGE_LOCKS     1024

/*
 * How the backing store holds the data (mbe_type). DRAM, the default, is one
 * allocation pinned up front, as FEMU always had. SPARSE maps anonymous memory
 * that takes host pages only for blocks written and gives them back when the
 * blocks are deallocated. FILE maps a host file, so the host page cache holds
 * the data and the kernel writes it back. DRAM is 0 so that a backend another
 * device lends, zero-initialized, keeps the old behavior.
 */
typedef enum FemuMbeType {
    FEMU_MBE_DRAM = 0,
    FEMU_MBE_SPARSE,
    FEMU_MBE_FILE,
} FemuMbeType;

/* the mbe_* properties, as init_dram_backend() takes them */
typedef struct FemuMbeConfig {
    FemuMbeType type;
    const char *file;   /* FILE: the host file holding the data */
    bool thp;           /* SPARSE: let the host back it with huge pages */
    bool lock;          /* SPARSE: keep pages resident once written */
    bool pin_meta;      /* SPARSE/FILE: pin all other process memory */
} FemuMbeConfig;

/* DRAM backend SSD address space */
typedef struct SsdDramBackend {
    void    *logical_space;
    int64_t size; /* in bytes */
    int     femu_mode;
    FemuMbeType type;
    int     fd;           /* FILE: the mapped file */
    bool    locked;       /* SPARSE: pages stay resident once written */
    QemuMutex *range_locks; /* NULL: accesses take no lock */
    uint64_t range_waits;   /* lock takes that found the lock held */
} SsdDramBackend;

int femu_mbe_parse_type(const char *name, FemuMbeType *type, Error **errp);
int init_dram_backend(SsdDramBackend **mbe, int64_t nbytes,
                      const FemuMbeConfig *cfg, Error **errp);
void free_dram_backend(SsdDramBackend *);
void backend_zero_range(SsdDramBackend *b, uint64_t off, uint64_t len);
uint64_t backend_resident_bytes(SsdDramBackend *b);

int backend_rw(SsdDramBackend *, QEMUSGList *, uint64_t *, bool);
void backend_init_range_locks(SsdDramBackend *b);
void backend_free_range_locks(SsdDramBackend *b);
void backend_lock_range(SsdDramBackend *b, uint64_t off, uint64_t len);
void backend_unlock_range(SsdDramBackend *b, uint64_t off, uint64_t len);

#endif
