#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Estimate how much a zswap tier would hold of a disk image.

A mbe_type=sparse backend under a memory cgroup with zswap keeps cold data
compressed in DRAM. Whether that is worth setting up depends on the data:
logs and uncompressed database pages shrink two to four times, RocksDB SST
files, which compress their blocks themselves, hardly at all. Run this on an
image of the device after the target workload (dd the guest's disk, or the
mbe_file of a file backend) before planning on the compressed tier.

The image is read in 4 KiB pages, as zswap stores them. Pages of one byte
value repeated are counted apart: zswap keeps them without the compressor,
and a sparse backend never stores a page of zeros the guest deallocated.
Every other page is compressed alone, with lz4 when the lz4 module is
installed (zswap's usual compressor) and otherwise with zlib at level 1,
which compresses a little better than lz4 and says so in the report.

  lessdram-compress-ratio.py IMAGE [--sample N]

--sample N reads every Nth page only, for large images.
"""

import argparse
import os
import sys
import zlib

PAGE = 4096

try:
    import lz4.block

    def compress(page):
        return len(lz4.block.compress(page, store_size=False))

    COMPRESSOR = "lz4"
except ImportError:
    def compress(page):
        return len(zlib.compress(page, 1))

    COMPRESSOR = "zlib level 1 (lz4 module not installed; lz4 does worse)"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("--sample", type=int, default=1,
                    help="read every Nth page only")
    args = ap.parse_args()
    if args.sample < 1:
        ap.error("--sample must be at least 1")

    size = os.path.getsize(args.image)
    pages = zeros = same = other = 0
    stored = 0
    with open(args.image, "rb") as f:
        for i in range(0, size // PAGE, args.sample):
            f.seek(i * PAGE)
            page = f.read(PAGE)
            if len(page) < PAGE:
                break
            pages += 1
            if page.count(page[0]) == PAGE:
                if page[0] == 0:
                    zeros += 1
                else:
                    same += 1
                continue
            other += 1
            # zswap rejects a page that does not shrink and swaps it out
            stored += min(compress(page), PAGE)

    if not pages:
        sys.exit("lessdram-compress-ratio: no whole page in %s" % args.image)

    def pct(n):
        return 100.0 * n / pages

    print("image        %s, %.1f MiB, %d pages read (every %d)" %
          (args.image, size / 2**20, pages, args.sample))
    print("compressor   %s" % COMPRESSOR)
    print("zero pages   %6.2f %%" % pct(zeros))
    print("same-filled  %6.2f %%" % pct(same))
    print("other pages  %6.2f %%" % pct(other))
    if other:
        print("compression  %.2fx on the other pages (%.0f bytes per page)" %
              (other * PAGE / stored, stored / other))
    print("zswap holds  %.1f MiB per GiB of image (zero and same-filled "
          "pages take none)" % (stored / (pages * PAGE) * 1024))


if __name__ == "__main__":
    main()
