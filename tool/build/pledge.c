/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#ifdef __COSMOPOLITAN__
#include "libc/assert.h"
#include "libc/calls/calls.h"
#include "libc/calls/landlock.h"
#include "libc/calls/pledge.h"
#include "libc/calls/pledge.internal.h"
#include "libc/calls/struct/rlimit.h"
#include "libc/calls/struct/sched_param.h"
#include "libc/calls/struct/seccomp.h"
#include "libc/calls/struct/stat.h"
#include "libc/calls/struct/sysinfo.h"
#include "libc/calls/syscall-sysv.internal.h"
#include "libc/calls/syscall_support-sysv.internal.h"
#include "libc/dce.h"
#include "libc/elf/def.h"
#include "libc/elf/struct/ehdr.h"
#include "libc/errno.h"
#include "libc/fmt/conv.h"
#include "libc/intrin/bits.h"
#include "libc/intrin/kprintf.h"
#include "libc/intrin/promises.internal.h"
#include "libc/intrin/safemacros.internal.h"
#include "libc/macros.internal.h"
#include "libc/math.h"
#include "libc/mem/copyfd.internal.h"
#include "libc/mem/gc.internal.h"
#include "libc/mem/mem.h"
#include "libc/nexgen32e/kcpuids.h"
#include "libc/runtime/runtime.h"
#include "libc/sock/sock.h"
#include "libc/sock/struct/pollfd.h"
#include "libc/stdio/stdio.h"
#include "libc/str/str.h"
#include "libc/sysv/consts/ioprio.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/ok.h"
#include "libc/sysv/consts/poll.h"
#include "libc/sysv/consts/pr.h"
#include "libc/sysv/consts/prio.h"
#include "libc/sysv/consts/prot.h"
#include "libc/sysv/consts/rlim.h"
#include "libc/sysv/consts/rlimit.h"
#include "libc/sysv/consts/sched.h"
#include "libc/sysv/errfuns.h"
#include "libc/x/x.h"
#include "third_party/getopt/getopt.h"

// MANUALLY TESTED BY RUNNING
//
//     test/tool/build/pledge_test.sh
//

STATIC_YOINK("strerror_wr");
STATIC_YOINK("zip_uri_support");

#else

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/fsuid.h>
#include <ctype.h>
#include <string.h>
#include <libgen.h>
#include <math.h>
#include <sys/param.h>
#include <linux/landlock.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/ioprio.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

static unsigned _getcpucount(void) {
  cpu_set_t s = {0};
  if (sched_getaffinity(0, sizeof(s), &s) != -1) {
    return CPU_COUNT(&s);
  } else {
    return 0;
  }
}

static int GetExponent(int c) {
  switch (c) {
    case '\0':
    case ' ':
    case '\t':
      return 0;
    case 'k':
    case 'K':
      return 1;
    case 'm':
    case 'M':
      return 2;
    case 'g':
    case 'G':
      return 3;
    case 't':
    case 'T':
      return 4;
    case 'p':
    case 'P':
      return 5;
    case 'e':
    case 'E':
      return 6;
    default:
      return -1;
  }
}

/**
 * Converts size string to long.
 *
 * The following unit suffixes may be used
 *
 * - `k` or `K` for kilo (multiply by 𝑏¹)
 * - `m` or `M` for mega (multiply by 𝑏²)
 * - `g` or `G` for giga (multiply by 𝑏³)
 * - `t` or `T` for tera (multiply by 𝑏⁴)
 * - `p` or `P` for peta (multiply by 𝑏⁵)
 * - `e` or `E` for exa  (multiply by 𝑏⁶)
 *
 * If a permitted alpha character is supplied, then any additional
 * characters after it (e.g. kbit, Mibit, TiB) are ignored. Spaces
 * before the integer are ignored, and overflows will be detected.
 *
 * Negative numbers are permissible, as well as a leading `+` sign. To
 * tell the difference between an error return and `-1` you must clear
 * `errno` before calling and test whether it changed.
 *
 * @param s is non-null nul-terminated input string
 * @param b is multiplier which should be 1000 or 1024
 * @return size greater than or equal 0 or -1 on error
 * @error EINVAL if error is due to bad syntax
 * @error EOVERFLOW if error is due to overflow
 */
long sizetol(const char *s, long b) {
  long x;
  int c, e, d;
  do {
    c = *s++;
  } while (c == ' ' || c == '\t');
  d = c == '-' ? -1 : 1;
  if (c == '-' || c == '+') c = *s++;
  if (!isdigit(c)) {
    errno = EINVAL;
    return -1;
  }
  x = 0;
  do {
    if (__builtin_mul_overflow(x, 10, &x) ||
        __builtin_add_overflow(x, (c - '0') * d, &x)) {
      errno = EOVERFLOW;
      return -1;
    }
  } while (isdigit((c = *s++)));
  if ((e = GetExponent(c)) == -1) {
    errno = EINVAL;
    return -1;
  }
  while (e--) {
    if (__builtin_mul_overflow(x, b, &x)) {
      errno = EOVERFLOW;
      return -1;
    }
  }
  return x;
}

#define kprintf printf

void xdie(void) {
//  if (_weaken(__die)) __die();
  abort();
}

/**
 * Allocates uninitialized memory, or dies.
 */
void *xmalloc(size_t bytes) {
  void *res = malloc(bytes);
  if (!res) xdie();
  return res;
}

/**
 * Allocates/expands/shrinks/frees memory, or die.
 *
 * This API enables you to do the following:
 *
 *     p = xrealloc(p, n)
 *
 * The standard behaviors for realloc() still apply:
 *
 * - `!p` means xmalloc (returns non-NULL)
 * - `p && n` means resize (returns non-NULL)
 * - `p && !n` means free (returns NULL)
 *
 * The complexity of resizing is guaranteed to be amortized.
 */
void *xrealloc(void *p, size_t n) {
  void *q;
  q = realloc(p, n);
  if (!q && !(p && !n)) xdie();
  return q;
}

/**
 * Concatenates strings / chars to newly allocated memory, e.g.
 *
 *     xstrcat("hi", ' ', "there")
 *
 * Or without the C99 helper macro:
 *
 *     (xstrcat)("hi", ' ', "there", NULL)
 *
 * This goes twice as fast as the more powerful xasprintf(). It's not
 * quadratic like strcat(). It's much slower than high-effort stpcpy(),
 * particularly with string literals.
 *
 * @see gc()
 */
char *(xstrcat)(const char *s, ...) {
  va_list va;
  intptr_t q;
  char *p, b[2];
  size_t n, m, c;
  n = 0;
  c = 32;
  p = xmalloc(c);
  va_start(va, s);
  do {
    q = (intptr_t)s;
    if (q > 0 && q <= 255) {
      b[0] = q;
      b[1] = '\0';
      s = b;
      m = 1;
    } else {
      m = strlen(s);
    }
    if (n + m + 1 > c) {
      do {
        c += c >> 1;
      } while (n + m + 1 > c);
      p = xrealloc(p, c);
    }
    memcpy(p + n, s, m + 1);
    n += m;
  } while ((s = va_arg(va, const char *)));
  va_end(va);
  return p;
}

/**
 * Create new Landlock filesystem sandboxing ruleset.
 *
 * You may also use this function to query the current ABI version:
 *
 *     landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION);
 *
 * @return close exec file descriptor for new ruleset
 * @error ENOSYS if not running Linux 5.13+
 * @error EPERM if pledge() or seccomp bpf shut it down
 * @error EOPNOTSUPP Landlock supported but disabled at boot
 * @error EINVAL unknown flags, or unknown access, or too small size
 * @error E2BIG attr or size inconsistencies
 * @error EFAULT attr or size inconsistencies
 * @error ENOMSG empty landlock_ruleset_attr::handled_access_fs
 */
int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
                            size_t size, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_create_ruleset, attr, size, flags);
  if (rc < 0) {
    errno = -rc;
    return rc;
  }
  return rc;
}

/**
 * Adds new rule to Landlock ruleset.
 *
 * @error ENOSYS if Landlock isn't supported
 * @error EPERM if Landlock supported but SECCOMP BPF shut it down
 * @error EOPNOTSUPP if Landlock supported but disabled at boot time
 * @error EINVAL if flags not 0, or inconsistent access in the rule,
 *     i.e. landlock_path_beneath_attr::allowed_access is not a subset
 *     of the ruleset handled accesses
 * @error ENOMSG empty allowed_access
 * @error EBADF `fd` is not a file descriptor for current thread, or
 *     member of `rule_attr` is not a file descriptor as expected
 * @error EBADFD `fd` is not a ruleset file descriptor, or a member
 *     of `rule_attr` is not the expected file descriptor type
 * @error EPERM `fd` has no write access to the underlying ruleset
 * @error EFAULT `rule_attr` inconsistency
 */
int landlock_add_rule(int fd, enum landlock_rule_type rule_type,
                      const void *rule_attr, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_add_rule, fd, rule_type, rule_attr, flags);
  if (rc < 0) {
    errno = -rc;
    return rc;
  }
  //KERNTRACE("landlock_add_rule(%d, %d, %p, %#x) → %d% m", fd, rule_type,
  //          rule_attr, flags, rc);
  return rc;
}

/**
 * Enforces Landlock ruleset on calling thread.
 *
 * @error EOPNOTSUPP if Landlock supported but disabled at boot time
 * @error EINVAL if flags isn't zero
 * @error EBADF if `fd` isn't file descriptor for the current thread
 * @error EBADFD if `fd` is not a ruleset file descriptor
 * @error EPERM if `fd` has no read access to underlying ruleset, or
 *     current thread is not running with no_new_privs, or it doesn’t
 *     have CAP_SYS_ADMIN in its namespace
 * @error E2BIG if the maximum number of stacked rulesets is
 *     reached for current thread
 */
int landlock_restrict_self(int fd, uint32_t flags) {
  int rc;
  rc = syscall(__NR_landlock_restrict_self, fd, flags);
  if (rc < 0) {
    errno = -rc;
    return rc;
  }
  //KERNTRACE("landlock_create_ruleset(%d, %#x) → %d% m", fd, flags, rc);
  return rc;
}

void CheckLargeStackAllocation(void *p, ssize_t n) {
  for (; n > 0; n -= 4096) {
    ((char *)p)[n - 1] = 0;
  }
}

#define ARRAYLEN(A)                                                     \
  ((sizeof(A) / sizeof(*(A))) / ((unsigned)!(sizeof(A) % sizeof(*(A)))))

/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/


#define OFF(f) offsetof(struct seccomp_data, f)

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#define UNVEIL_READ                                             \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
   LANDLOCK_ACCESS_FS_REFER)
#define UNVEIL_WRITE (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE)
#define UNVEIL_EXEC  (LANDLOCK_ACCESS_FS_EXECUTE)
#define UNVEIL_CREATE                                             \
  (LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |   \
   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |   \
   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
   LANDLOCK_ACCESS_FS_MAKE_SYM)

#define FILE_BITS                                                 \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
   LANDLOCK_ACCESS_FS_EXECUTE)


static struct sock_filter kUnveilBlacklistAbiVersionBelow3[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(arch)),
//    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
//    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_truncate, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setxattr, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static struct sock_filter kUnveilBlacklistLatestAbi[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(arch)),
//    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
//    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setxattr, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (1 & SECCOMP_RET_DATA)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static int landlock_abi_version;

__attribute__((__constructor__)) void init_landlock_version() {
  landlock_abi_version = landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION);
}

/**
 * Long living state for landlock calls.
 * fs_mask is set to use all the access rights from the latest landlock ABI.
 * On init, the current supported abi is checked and unavailable rights are
 * masked off.
 *
 * As of 6.2, the latest abi is v3.
 *
 * TODO:
 *  - Integrate with pledge and remove the file access?
 *  - Stuff state into the .protected section?
 */
_Thread_local static struct {
  uint64_t fs_mask;
  int fd;
} State;

static int unveil_final(void) {
  int e, rc;
  struct sock_fprog sandbox = {
      .filter = kUnveilBlacklistLatestAbi,
      .len = ARRAYLEN(kUnveilBlacklistLatestAbi),
  };
  if (landlock_abi_version < 3) {
    sandbox = (struct sock_fprog){
      .filter = kUnveilBlacklistAbiVersionBelow3,
      .len = ARRAYLEN(kUnveilBlacklistAbiVersionBelow3),
    };
  }
  e = errno;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  errno = e;
  if ((rc = landlock_restrict_self(State.fd, 0)) != -1 &&
      (rc = close(State.fd)) != -1 &&
      (rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sandbox)) != -1) {
    State.fd = 0;
  }
  return rc;
}

static int err_close(int rc, int fd) {
  int serrno = errno;
  close(fd);
  errno = serrno;
  return rc;
}

static int unveil_init(void) {
  int rc, fd;
  State.fs_mask = UNVEIL_READ | UNVEIL_WRITE | UNVEIL_EXEC | UNVEIL_CREATE;
  if (landlock_abi_version == -1) {
    if (errno == EOPNOTSUPP) {
      errno = ENOSYS;
    }
    return -1;
  }
  if (landlock_abi_version < 2) {
    State.fs_mask &= ~LANDLOCK_ACCESS_FS_REFER;
  }
  if (landlock_abi_version < 3) {
    State.fs_mask &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  const struct landlock_ruleset_attr attr = {
      .handled_access_fs = State.fs_mask,
  };
  // [undocumented] landlock_create_ruleset() always returns o_cloexec
  //                assert(__sys_fcntl(rc, F_GETFD, 0) == FD_CLOEXEC);
  if ((rc = landlock_create_ruleset(&attr, sizeof(attr), 0)) < 0) return -1;
  // grant file descriptor a higher number that's less likely to interfere
  if ((fd = fcntl(rc, F_DUPFD_CLOEXEC, 100)) == -1) {
    return err_close(-1, rc);
  }
  if (close(rc) == -1) {
    return err_close(-1, fd);
  }
  State.fd = fd;
  return 0;
}

/**
 * Joins paths, e.g.
 *
 *     0    + 0    → 0
 *     ""   + ""   → ""
 *     "a"  + 0    → "a"
 *     "a"  + ""   → "a/"
 *     0    + "b"  → "b"
 *     ""   + "b"  → "b"
 *     "."  + "b"  → "./b"
 *     "b"  + "."  → "b/."
 *     "a"  + "b"  → "a/b"
 *     "a/" + "b"  → "a/b"
 *     "a"  + "b/" → "a/b/"
 *     "a"  + "/b" → "/b"
 *
 * @return joined path, which may be `buf`, `path`, or `other`, or null
 *     if (1) `buf` didn't have enough space, or (2) both `path` and
 *     `other` were null
 */
char *_joinpaths(char *buf, size_t size, const char *path, const char *other) {
  size_t pathlen, otherlen;
  if (!other) return (char *)path;
  if (!path) return (char *)other;
  pathlen = strlen(path);
  if (!pathlen || *other == '/') {
    return (/*unconst*/ char *)other;
  }
  otherlen = strlen(other);
  if (path[pathlen - 1] == '/') {
    if (pathlen + otherlen + 1 <= size) {
      memmove(buf, path, pathlen);
      memmove(buf + pathlen, other, otherlen + 1);
      return buf;
    } else {
      return 0;
    }
  } else {
    if (pathlen + 1 + otherlen + 1 <= size) {
      memmove(buf, path, pathlen);
      buf[pathlen] = '/';
      memmove(buf + pathlen + 1, other, otherlen + 1);
      return buf;
    } else {
      return 0;
    }
  }
}

int sys_unveil_linux(const char *path, const char *permissions) {
  int rc;
  const char *dir;
  const char *last;
  const char *next;
  struct {
    char lbuf[PATH_MAX];
    char buf1[PATH_MAX];
    char buf2[PATH_MAX];
    char buf3[PATH_MAX];
    char buf4[PATH_MAX];
  } b;
  CheckLargeStackAllocation(&b, sizeof(b));

  if (!State.fd && (rc = unveil_init()) == -1) return rc;
  if ((path && !permissions) || (!path && permissions)) {
    errno = EINVAL;
    return -1;
  }
  if (!path && !permissions) return unveil_final();
  struct landlock_path_beneath_attr pb = {0};
  for (const char *c = permissions; *c != '\0'; c++) {
    switch (*c) {
      case 'r':
        pb.allowed_access |= UNVEIL_READ;
        break;
      case 'w':
        pb.allowed_access |= UNVEIL_WRITE;
        break;
      case 'x':
        pb.allowed_access |= UNVEIL_EXEC;
        break;
      case 'c':
        pb.allowed_access |= UNVEIL_CREATE;
        break;
      default:
        errno = EINVAL;
        return -1;
    }
  }
  pb.allowed_access &= State.fs_mask;

  // landlock exposes all metadata, so we only technically need to add
  // realpath(path) to the ruleset. however a corner case exists where
  // it isn't valid, e.g. /dev/stdin -> /proc/2834/fd/pipe:[51032], so
  // we'll need to work around this, by adding the path which is valid
  if (strlen(path) + 1 > PATH_MAX) {
    errno = ENAMETOOLONG;
    return -1;
  }
  last = path;
  next = path;
  for (int i = 0;; ++i) {
    if (i == 64) {
      // give up
      errno = ELOOP;
      return -1;
    }
    int err = errno;
    if ((rc = readlinkat(AT_FDCWD, next, b.lbuf, PATH_MAX)) != -1) {
      if (rc < PATH_MAX) {
        // we need to nul-terminate
        b.lbuf[rc] = 0;
        // last = next
        strcpy(b.buf1, next);
        last = b.buf1;
        // next = join(dirname(next), link)
        strcpy(b.buf2, next);
        dir = dirname(b.buf2);
        if ((next = _joinpaths(b.buf3, PATH_MAX, dir, b.lbuf))) {
          // next now points to either: buf3, buf2, lbuf, rodata
          strcpy(b.buf4, next);
          next = b.buf4;
        } else {
          errno = ENAMETOOLONG;
          return -1;
        }
      } else {
        // symbolic link data was too long
        errno = ENAMETOOLONG;
        return -1;
      }
    } else if (errno == EINVAL) {
      // next wasn't a symbolic link
      errno = err;
      path = next;
      break;
    } else if (i && (errno == ENOENT || errno == ENOTDIR)) {
      // next is a broken symlink, use last
      errno = err;
      path = last;
      break;
    } else {
      // readlink failed for some other reason
      return -1;
    }
  }

  // now we can open the path
  //BLOCK_CANCELLATIONS;
  rc = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC, 0);
  //ALLOW_CANCELLATIONS;
  if (rc == -1) return rc;

  pb.parent_fd = rc;
  struct stat st;
  if ((rc = fstat(pb.parent_fd, &st)) == -1) {
    return err_close(rc, pb.parent_fd);
  }
  if (!S_ISDIR(st.st_mode)) {
    pb.allowed_access &= FILE_BITS;
  }
  if ((rc = landlock_add_rule(State.fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0))) {
    return err_close(rc, pb.parent_fd);
  }
  close(pb.parent_fd);
  return rc;
}

/**
 * Makes files accessible, e.g.
 *
 *     unveil(".", "r");     // current directory + children are visible
 *     unveil("/etc", "r");  // make /etc readable too
 *     unveil(0, 0);         // commit and lock policy
 *
 * Unveiling restricts a view of the filesystem to a set of allowed
 * paths with specific privileges.
 *
 * Once you start using unveil(), the entire file system is considered
 * hidden. You then specify, by repeatedly calling unveil(), which paths
 * should become unhidden. When you're finished, you call `unveil(0,0)`
 * which commits your policy.
 *
 * This function requires OpenBSD or Linux 5.13+. We don't consider lack
 * of system support to be an ENOSYS error, because the files will still
 * become unveiled. Therefore we return 0 in such cases.
 *
 * There are some differences between unveil() on Linux versus OpenBSD.
 *
 * 1. Build your policy and lock it in one go. On OpenBSD, policies take
 *    effect immediately and may evolve as you continue to call unveil()
 *    but only in a more restrictive direction. On Linux, nothing will
 *    happen until you call `unveil(0,0)` which commits and locks.
 *
 * 2. Try not to overlap directory trees. On OpenBSD, if directory trees
 *    overlap, then the most restrictive policy will be used for a given
 *    file. On Linux overlapping may result in a less restrictive policy
 *    and possibly even undefined behavior.
 *
 * 3. OpenBSD and Linux disagree on error codes. On OpenBSD, accessing
 *    paths outside of the allowed set raises ENOENT, and accessing ones
 *    with incorrect permissions raises EACCES. On Linux, both these
 *    cases raise EACCES.
 *
 * 4. Unlike OpenBSD, Linux does nothing to conceal the existence of
 *    paths. Even with an unveil() policy in place, it's still possible
 *    to access the metadata of all files using functions like stat()
 *    and open(O_PATH), provided you know the path. A sandboxed process
 *    can always, for example, determine how many bytes of data are in
 *    /etc/passwd, even if the file isn't readable. But it's still not
 *    possible to use opendir() and go fishing for paths which weren't
 *    previously known.
 *
 * 5. Use ftruncate() rather than truncate() if you wish for portability to
 *    Linux kernels versions released before February 2022. One issue
 *    Landlock hadn't addressed as of ABI version 2 was restrictions over
 *    truncate() and setxattr() which could permit certain kinds of
 *    modifications to files outside the sandbox. When your policy is
 *    committed, we install a SECCOMP BPF filter to disable those calls,
 *    however similar trickery may be possible through other unaddressed
 *    calls like ioctl(). Using the pledge() function in addition to
 *    unveil() will solve this, since it installs a strong system call
 *    access policy. Linux 6.2 has improved this situation with Landlock
 *    ABI v3, which added the ability to control truncation operations -
 *    this means the SECCOMP BPF filter will only disable
 *    truncate() on Linux 6.1 or older
 *
 * 6. Set your process-wide policy at startup from the main thread. On
 *    OpenBSD unveil() will apply process-wide even when called from a
 *    child thread; whereas with Linux, calling unveil() from a thread
 *    will cause your ruleset to only apply to that thread in addition
 *    to any descendent threads it creates.
 *
 * 7. Always specify at least one path. OpenBSD has unclear semantics
 *    when `unveil(0,0)` is used without any previous calls.
 *
 * 8. On OpenBSD calling `unveil(0,0)` will prevent unveil() from being
 *    used again. On Linux this is allowed, because Landlock is able to
 *    do that securely, i.e. the second ruleset can only be a subset of
 *    the previous ones.
 *
 * This system call is supported natively on OpenBSD and polyfilled on
 * Linux using the Landlock LSM[1].
 *
 * @param path is the file or directory to unveil
 * @param permissions is a string consisting of zero or more of the
 *     following characters:
 *
 *     - 'r' makes `path` available for read-only path operations,
 *       corresponding to the pledge promise "rpath".
 *
 *     - `w` makes `path` available for write operations, corresponding
 *       to the pledge promise "wpath".
 *
 *     - `x` makes `path` available for execute operations,
 *       corresponding to the pledge promises "exec" and "execnative".
 *
 *     - `c` allows `path` to be created and removed, corresponding to
 *       the pledge promise "cpath".
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if one argument is set and the other is not
 * @raise EINVAL if an invalid character in `permissions` was found
 * @raise EPERM if unveil() is called after locking
 * @note on Linux this function requires Linux Kernel 5.13+ and version 6.2+
 *     to properly support truncation operations
 * @see [1] https://docs.kernel.org/userspace-api/landlock.html
 * @threadsafe
 */
int unveil(const char *path, const char *permissions) {
  int e, rc;
  e = errno;
  rc = sys_unveil_linux(path, permissions);
  /*if (IsGenuineBlink()) {
    rc = 0;  // blink doesn't support landlock
  } else if (IsLinux()) {
    rc = sys_unveil_linux(path, permissions);
  } else {
    rc = sys_unveil(path, permissions);
  }*/
  if (rc == -1 && errno == ENOSYS) {
    errno = e;
    rc = 0;
  }
  //STRACE("unveil(%#s, %#s) → %d% m", path, permissions, rc);
  return rc;
}

#define PROMISE_STDIO     0
#define PROMISE_RPATH     1
#define PROMISE_WPATH     2
#define PROMISE_CPATH     3
#define PROMISE_DPATH     4
#define PROMISE_FLOCK     5
#define PROMISE_FATTR     6
#define PROMISE_INET      7
#define PROMISE_UNIX      8
#define PROMISE_DNS       9
#define PROMISE_TTY       10
#define PROMISE_RECVFD    11
#define PROMISE_PROC      12
#define PROMISE_EXEC      13
#define PROMISE_ID        14
#define PROMISE_UNVEIL    15
#define PROMISE_SENDFD    16
#define PROMISE_SETTIME   17
#define PROMISE_PROT_EXEC 18
#define PROMISE_VMINFO    19
#define PROMISE_TMPPATH   20
#define PROMISE_CHOWN     21
#define PROMISE_LEN_      22

#define UNLIKELY(x) x

/**
 * Allocates new copy of string, or dies.
 */
char *xstrdup(const char *s) {
  size_t len = strlen(s);
  char *s2 = malloc(len + 1);
  if (UNLIKELY(!s2)) xdie();
  return memcpy(s2, s, len + 1);
}

#define _kPathAbs  1
#define _kPathDev  2
#define _kPathRoot 4
#define _kPathDos  8
#define _kPathWin  16
#define _kPathNt   32

/**
 * Classifies file path name.
 *
 * For the purposes of this function, we always consider backslash
 * interchangeable with forward slash, even though the underlying
 * operating system might not. Therefore, for the sake of clarity,
 * remaining documentation will only use the forward slash.
 *
 * This function behaves the same on all platforms. For instance, this
 * function will categorize `C:/FOO.BAR` as a DOS path, even if you're
 * running on UNIX rather than DOS.
 *
 * If you wish to check if a pathname is absolute, in a manner that's
 * inclusive of DOS drive paths, DOS rooted paths, in addition to the
 * New Technology UNC paths, then you may do the following:
 *
 *     if (_classifypath(str) & _kPathAbs) { ... }
 *
 * To check if path is a relative path:
 *
 *     if (~_classifypath(str) & _kPathAbs) { ... }
 *
 * Please note the above check includes rooted paths such as `\foo`
 * which is considered absolute by MSDN and we consider it absolute
 * although, it's technically relative to the current drive letter.
 *
 * Please note that `/foo/bar` is an absolute path on Windows, even
 * though it's actually a rooted path that's considered relative to
 * current drive by WIN32.
 *
 * @return integer value that's one of following:
 *     - `0` if non-weird relative path e.g. `c`
 *     - `_kPathAbs` if absolute (or rooted dos) path e.g. `/⋯`
 *     - `_kPathDos` if `c:`, `d:foo` i.e. drive-relative path
 *     - `_kPathAbs|_kPathDos` if proper dos path e.g. `c:/foo`
 *     - `_kPathDos|_kPathDev` if dos device path e.g. `nul`, `conin$`
 *     - `_kPathAbs|_kPathWin` if `//c`, `//?c`, etc.
 *     - `_kPathAbs|_kPathWin|_kPathDev` if `//./⋯`, `//?/⋯`
 *     - `_kPathAbs|_kPathWin|_kPathDev|_kPathRoot` if `//.` or `//?`
 *     - `_kPathAbs|_kPathNt` e.g. `\??\\⋯` (undoc. strict backslash)
 * @see "The Definitive Guide on Win32 to NT Path Conversion", James
 *     Forshaw, Google Project Zero Blog, 2016-02-29
 * @see "Naming Files, Paths, and Namespaces", MSDN 01/04/2021
 */
int _classifypath(const char *s) {
  if (s) {
    switch (s[0]) {
      case 0:  // ""
        return 0;
      default:
        return 0;
      case '\\':
        // fallthrough
      case '/':
        return _kPathAbs;
    }
  } else {
    return 0;
  }
}

/**
 * Returns true if pathname is considered absolute.
 *
 * - `/home/jart/foo.txt` is absolute
 * - `C:/Users/jart/foo.txt` is absolute on Windows
 * - `C:\Users\jart\foo.txt` is absolute on Windows
 * - `\??\C:\Users\jart\foo.txt` is absolute on Windows
 * - `\\.\C:\Users\jart\foo.txt` is absolute on Windows
 * - `/Users/jart/foo.txt` is effectively absolute on Windows
 * - `\Users\jart\foo.txt` is effectively absolute on Windows
 *
 */
bool _isabspath(const char *path) {
  return _classifypath(path) & _kPathAbs;
}

/**
 * Returns true if s has suffix.
 *
 * @param s is a NUL-terminated string
 * @param suffix is also NUL-terminated
 */
bool _endswith(const char *s, const char *suffix) {
  size_t n, m;
  n = strlen(s);
  m = strlen(suffix);
  if (m > n) return false;
  return !memcmp(s + n - m, suffix, m);
}

/**
 * Joins paths, e.g.
 *
 *     "a"  + "b"  → "a/b"
 *     "a/" + "b"  → "a/b"
 *     "a"  + "b/" → "a/b/"
 *     "a"  + "/b" → "/b"
 *     "."  + "b"  → "b"
 *     ""   + "b"  → "b"
 *
 * @return newly allocated string of resulting path
 */
char *xjoinpaths(const char *path, const char *other) {
  if (!*other) {
    return xstrdup(path);
  } else if (!*path) {
    return xstrdup(other);
  } else if (_isabspath(other) || !strcmp(path, ".")) {
    return xstrdup(other);
  } else if (_endswith(path, "/")) {
    return xstrcat(path, other, NULL);
  } else {
    return xstrcat(path, '/', other, NULL);
  }
}

static bool AccessCommand(const char *name, char *path, size_t pathsz,
                          size_t namelen, int *err, const char *suffix,
                          size_t pathlen) {
  size_t suffixlen;
  suffixlen = strlen(suffix);
  /*if (IsWindows() && suffixlen == 0 && !IsExePath(name, namelen) &&
      !IsComPath(name, namelen))
    return false;*/
  if (pathlen + 1 + namelen + suffixlen + 1 > pathsz) return false;
  if (pathlen && (path[pathlen - 1] != '/' && path[pathlen - 1] != '\\')) {
    path[pathlen] = '/';
    pathlen++;
  }
  memcpy(path + pathlen, name, namelen);
  memcpy(path + pathlen + namelen, suffix, suffixlen + 1);
  if (!access(path, X_OK)) {
    struct stat st;
    if (!stat(path, &st)) {
      if (S_ISREG(st.st_mode)) {
        return true;
      } else {
        errno = EACCES;
      }
    }
  }
  if (errno == EACCES || *err != EACCES) *err = errno;
  return false;
}

static bool SearchPath(const char *name, char *path, size_t pathsz,
                       size_t namelen, int *err, const char *suffix) {
  char sep;
  size_t i;
  const char *p;
  if (!(p = getenv("PATH"))) p = "/bin:/usr/local/bin:/usr/bin";
  sep = ':';//IsWindows() && strchr(p, ';') ? ';' : ':';
  for (;;) {
    for (i = 0; p[i] && p[i] != sep; ++i) {
      if (i < pathsz) {
        path[i] = p[i];
      }
    }
    if (AccessCommand(name, path, pathsz, namelen, err, suffix, i)) {
      return true;
    }
    if (p[i] == sep) {
      p += i + 1;
    } else {
      break;
    }
  }
  return false;
}

static bool FindCommand(const char *name, char *pb, size_t pbsz, size_t namelen,
                        bool pri, const char *suffix, int *err) {
  if (pri && (memchr(name, '/', namelen) || memchr(name, '\\', namelen))) {
    pb[0] = 0;
    return AccessCommand(name, pb, pbsz, namelen, err, suffix, 0);
  }
  /*if (IsWindows() && pri &&
      pbsz > max(strlen(kNtSystemDirectory), strlen(kNtWindowsDirectory))) {
    return AccessCommand(name, pb, pbsz, namelen, err, suffix,
                         stpcpy(pb, kNtSystemDirectory) - pb) ||
           AccessCommand(name, pb, pbsz, namelen, err, suffix,
                         stpcpy(pb, kNtWindowsDirectory) - pb);
  }
  return (IsWindows() &&
          (pbsz > 1 && AccessCommand(name, pb, pbsz, namelen, err, suffix,
          stpcpy(pb, ".") - pb))) ||*/
  return SearchPath(name, pb, pbsz, namelen, err, suffix);
}

static bool FindVerbatim(const char *name, char *pb, size_t pbsz,
                         size_t namelen, bool pri, int *err) {
  return FindCommand(name, pb, pbsz, namelen, pri, "", err);
}

#define READ32LE(S)                                                    \
  ((uint32_t)(255 & (S)[3]) << 030 | (uint32_t)(255 & (S)[2]) << 020 | \
   (uint32_t)(255 & (S)[1]) << 010 | (uint32_t)(255 & (S)[0]) << 000)
#define READ64LE(S)                                                    \
  ((uint64_t)(255 & (S)[7]) << 070 | (uint64_t)(255 & (S)[6]) << 060 | \
   (uint64_t)(255 & (S)[5]) << 050 | (uint64_t)(255 & (S)[4]) << 040 | \
   (uint64_t)(255 & (S)[3]) << 030 | (uint64_t)(255 & (S)[2]) << 020 | \
   (uint64_t)(255 & (S)[1]) << 010 | (uint64_t)(255 & (S)[0]) << 000)

static bool IsExePath(const char *s, size_t n) {
  return n >= 4 && (READ32LE(s + n - 4) == READ32LE(".exe") ||
                    READ32LE(s + n - 4) == READ32LE(".EXE"));
}

static bool IsComPath(const char *s, size_t n) {
  return n >= 4 && (READ32LE(s + n - 4) == READ32LE(".com") ||
                    READ32LE(s + n - 4) == READ32LE(".COM"));
}

static bool IsComDbgPath(const char *s, size_t n) {
  return n >= 8 && (READ64LE(s + n - 8) == READ64LE(".com.dbg") ||
                    READ64LE(s + n - 8) == READ64LE(".COM.DBG"));
}

static bool FindSuffixed(const char *name, char *pb, size_t pbsz,
                         size_t namelen, bool pri, int *err) {
  return !IsExePath(name, namelen) && !IsComPath(name, namelen) &&
         !IsComDbgPath(name, namelen) &&
         (FindCommand(name, pb, pbsz, namelen, pri, ".com", err) ||
          FindCommand(name, pb, pbsz, namelen, pri, ".exe", err));
}

/**
 * Resolves full pathname of executable.
 *
 * @return execve()'able path, or NULL w/ errno
 * @errno ENOENT, EACCES, ENOMEM
 * @see free(), execvpe()
 * @asyncsignalsafe
 * @vforksafe
 */
char *commandv(const char *name, char *pathbuf, size_t pathbufsz) {
  int e, f;
  char *res;
  size_t namelen;
  res = 0;
  if (!name) {
    errno = EFAULT;
    return NULL;
  } else if (!(namelen = strlen(name))) {
    errno = ENOENT;
    return NULL;
  } else if (namelen + 1 > pathbufsz) {
    errno = ENAMETOOLONG;
    return NULL;
  } else {
    e = errno;
    f = ENOENT;
    if ((true &&
         (FindVerbatim(name, pathbuf, pathbufsz, namelen, true, &f) ||
          FindSuffixed(name, pathbuf, pathbufsz, namelen, true, &f) ||
          FindVerbatim(name, pathbuf, pathbufsz, namelen, false, &f) ||
          FindSuffixed(name, pathbuf, pathbufsz, namelen, false, &f)))) {
      errno = e;
      res = pathbuf;
    } else {
      errno = f;
    }
  }
  //STRACE("commandv(%#s, %p, %'zu) → %#s% m", name, pathbuf, pathbufsz, res);
  return res;
}

#define PLEDGE(pledge) pledge, ARRAYLEN(pledge)

struct Pledges {
  const char *name;
  const uint16_t *syscalls;
  const size_t len;
};

static const uint16_t kPledgeDefault[] = {
    __NR_exit,  // thread return / exit()
};

#define SPECIAL   0xf000
#define SELF      0x8000
#define ADDRLESS  0x2000
#define INET      0x2000
#define LOCK      0x4000
#define NOEXEC    0x8000
#define EXEC      0x4000
#define READONLY  0x8000
#define WRITEONLY 0x4000
#define CREATONLY 0x2000
#define STDIO     0x8000
#define THREAD    0x8000
#define TTY       0x8000
#define UNIX      0x4000
#define NOBITS    0x8000
#define RESTRICT  0x1000

// stdio contains all the benign system calls. openbsd makes the
// assumption that preexisting file descriptors are trustworthy. we
// implement checking for these as a simple linear scan rather than
// binary search, since there doesn't appear to be any measurable
// difference in the latency of sched_yield() if it's at the start of
// the bpf script or the end.
static const uint16_t kPledgeStdio[] = {
#ifdef __NR_sigreturn
    __NR_sigreturn,          //
#endif
    __NR_restart_syscall,    //
    __NR_exit_group,         //
    __NR_sched_yield,        //
    __NR_sched_getaffinity,  //
    __NR_clock_getres,       //
    __NR_clock_gettime,      //
    __NR_clock_nanosleep,    //
    __NR_close_range,        //
    __NR_close,              //
    __NR_write,              //
    __NR_writev,             //
#ifdef __NR_pwrite
    __NR_pwrite,             //
#endif
    __NR_pwrite64,           //
    __NR_pwritev,            //
    __NR_pwritev2,           //
    __NR_read,               //
    __NR_readv,              //
#ifdef __NR_pread
    __NR_pread,              //
#endif
    __NR_pread64,            //
    __NR_preadv,             //
    __NR_preadv2,            //
    __NR_dup,                //
#ifdef __NR_dup2
    __NR_dup2,               //
#endif
    __NR_dup3,               //
    __NR_fchdir,             //
    __NR_fcntl | STDIO,      //
    __NR_fstat,              //
    __NR_fsync,              //
    __NR_sysinfo,            //
    __NR_fdatasync,          //
    __NR_ftruncate,          //
    __NR_getrandom,          //
    __NR_getgroups,          //
    __NR_getpgid,            //
#ifdef __NR_getpgrp
    __NR_getpgrp,            //
#endif
    __NR_getpid,             //
    __NR_gettid,             //
    __NR_getuid,             //
    __NR_getgid,             //
    __NR_getsid,             //
    __NR_getppid,            //
    __NR_geteuid,            //
    __NR_getegid,            //
    __NR_getrlimit,          //
    __NR_getresgid,          //
    __NR_getresuid,          //
    __NR_getitimer,          //
    __NR_setitimer,          //
    __NR_timerfd_create,     //
    __NR_timerfd_settime,    //
    __NR_timerfd_gettime,    //
    __NR_copy_file_range,    //
    __NR_gettimeofday,       //
    __NR_sendfile,           //
    __NR_vmsplice,           //
    __NR_splice,             //
    __NR_lseek,              //
    __NR_tee,                //
    __NR_brk,                //
    __NR_msync,              //
    __NR_mmap | NOEXEC,      //
    __NR_mremap,             //
    __NR_munmap,             //
    __NR_mincore,            //
    __NR_madvise,            //
    __NR_fadvise64,          //
    __NR_mprotect | NOEXEC,  //
#ifdef __NR_arch_prctl
    __NR_arch_prctl,         //
#endif
    __NR_migrate_pages,      //
    __NR_sync_file_range,    //
    __NR_set_tid_address,    //
    __NR_membarrier,         //
    __NR_nanosleep,          //
#ifdef __NR_pipe
    __NR_pipe,               //
#endif
    __NR_pipe2,              //
#ifdef __NR_poll
    __NR_poll,               //
#endif
    __NR_ppoll,              //
#ifdef __NR_select
    __NR_select,             //
#endif
#ifdef __NR_newselect
    __NR_newselect,          //
#endif
    __NR_pselect6,           //
#ifdef __NR_epoll_create
    __NR_epoll_create,       //
#endif
    __NR_epoll_create1,      //
    __NR_epoll_ctl,          //
#ifdef __NR_epoll_wait
    __NR_epoll_wait,         //
#endif
    __NR_epoll_pwait,        //
    __NR_epoll_pwait2,       //
    __NR_recvfrom,           //
    __NR_sendto | ADDRLESS,  //
    __NR_ioctl,   //
#ifdef __NR_alarm
    __NR_alarm,              //
#endif
#ifdef __NR_pause
    __NR_pause,              //
#endif
    __NR_shutdown,           //
#ifdef __NR_eventfd
    __NR_eventfd,            //
#endif
    __NR_eventfd2,           //
#ifdef __NR_signalfd
    __NR_signalfd,           //
#endif
    __NR_signalfd4,          //
#ifdef __NR_rt_sigaction
    __NR_rt_sigaction,          //
#endif
    __NR_sigaltstack,        //
#ifdef __NR_rt_sigprocmask
    __NR_rt_sigprocmask,        //
#endif
#ifdef __NR_rt_sigsuspend
    __NR_rt_sigsuspend,         //
#endif
#ifdef __NR_rt_sigpending
    __NR_rt_sigpending,         //
#endif
    __NR_kill | SELF,        //
    __NR_tkill,              //
    __NR_tgkill | SELF,      //
    __NR_socketpair,         //
    __NR_getrusage,          //
    __NR_times,              //
    __NR_umask,              //
    __NR_wait4,              //
    __NR_uname,              //
    __NR_prctl | STDIO,      //
    __NR_clone | THREAD,     //
    __NR_futex,              //
    __NR_set_robust_list,    //
    __NR_get_robust_list,    //
    __NR_prlimit64 | STDIO,  //
    __NR_sched_getaffinity,  //
    __NR_sched_setaffinity,  //
#ifdef __NR_sigtimedwait
    __NR_sigtimedwait,       //
#endif
};

static const uint16_t kPledgeFlock[] = {
    __NR_flock,         //
    __NR_fcntl | LOCK,  //
};

static const uint16_t kPledgeRpath[] = {
    __NR_chdir,              //
    __NR_getcwd,             //
#ifdef __NR_open
    __NR_open | READONLY,    //
#endif
    __NR_openat | READONLY,  //
#ifdef __NR_stat
    __NR_stat,               //
#endif
#ifdef __NR_lstat
    __NR_lstat,              //
#endif
    __NR_fstat,              //
#ifdef __NR_fstatat64
    __NR_fstatat64,          //
#endif
#ifdef __NR_newfstatat
    __NR_newfstatat,          //
#endif
#ifdef __NR_access
    __NR_access,             //
#endif
    __NR_faccessat,          //
    __NR_faccessat2,         //
#ifdef __NR_readlink
    __NR_readlink,           //
#endif
    __NR_readlinkat,         //
    __NR_statfs,             //
    __NR_fstatfs,            //
#ifdef __NR_getdents
    __NR_getdents,           //
#endif
    __NR_getdents64,         //
};

static const uint16_t kPledgeWpath[] = {
    __NR_getcwd,              //
#ifdef __NR_open
    __NR_open | WRITEONLY,    //
#endif
    __NR_openat | WRITEONLY,  //
#ifdef __NR_stat
    __NR_stat,                //
#endif
    __NR_fstat,               //
#ifdef __NR_lstat
    __NR_lstat,               //
#endif
#ifdef __NR_fstatat64
    __NR_fstatat64,           //
#endif
#ifdef __NR_newfstatat
    __NR_newfstatat,          //
#endif
#ifdef __NR_access
    __NR_access,              //
#endif
    __NR_truncate,            //
    __NR_faccessat,           //
    __NR_faccessat2,          //
    __NR_readlinkat,          //
#ifdef __NR_chmod
    __NR_chmod | NOBITS,      //
#endif
    __NR_fchmod | NOBITS,     //
    __NR_fchmodat | NOBITS,   //
};

static const uint16_t kPledgeCpath[] = {
#ifdef __NR_open
    __NR_open | CREATONLY,    //
#endif
    __NR_openat | CREATONLY,  //
#ifdef __NR_creat
    __NR_creat | RESTRICT,    //
#endif
#ifdef __NR_rename
    __NR_rename,              //
#endif
    __NR_renameat,            //
    __NR_renameat2,           //
#ifdef __NR_link
    __NR_link,                //
#endif
    __NR_linkat,              //
#ifdef __NR_symlink
    __NR_symlink,             //
#endif
    __NR_symlinkat,           //
#ifdef __NR_rmdir
    __NR_rmdir,               //
#endif
#ifdef __NR_unlink
    __NR_unlink,              //
#endif
    __NR_unlinkat,            //
#ifdef __NR_mkdir
    __NR_mkdir,               //
#endif
    __NR_mkdirat,             //
};

static const uint16_t kPledgeDpath[] = {
#ifdef __NR_mknod
    __NR_mknod,    //
#endif
    __NR_mknodat,  //
};

static const uint16_t kPledgeFattr[] = {
#ifdef __NR_chmod
    __NR_chmod | NOBITS,     //
#endif
    __NR_fchmod | NOBITS,    //
    __NR_fchmodat | NOBITS,  //
#ifdef __NR_utime
    __NR_utime,              //
#endif
#ifdef __NR_utimes
    __NR_utimes,             //
#endif
#ifdef __NR_futimesat
    __NR_futimesat,          //
#endif
    __NR_utimensat,          //
};

static const uint16_t kPledgeInet[] = {
    __NR_socket | INET,          //
    __NR_listen,                 //
    __NR_bind,                   //
    __NR_sendto,                 //
    __NR_connect,                //
    __NR_accept,                 //
    __NR_accept4,                //
    __NR_ioctl,           //
    __NR_getsockopt | RESTRICT,  //
    __NR_setsockopt | RESTRICT,  //
    __NR_getpeername,            //
    __NR_getsockname,            //
};

static const uint16_t kPledgeUnix[] = {
    __NR_socket | UNIX,          //
    __NR_listen,                 //
    __NR_bind,                   //
    __NR_connect,                //
    __NR_sendto,                 //
    __NR_accept,                 //
    __NR_accept4,                //
    __NR_getsockopt | RESTRICT,  //
    __NR_setsockopt | RESTRICT,  //
    __NR_getpeername,            //
    __NR_getsockname,            //
};

static const uint16_t kPledgeDns[] = {
    __NR_socket | INET,          //
    __NR_bind,                   //
    __NR_sendto,                 //
    __NR_connect,                //
    __NR_recvfrom,               //
    __NR_setsockopt | RESTRICT,  //
#ifdef __NR_fstatat64
    __NR_fstatat64,              //
#endif
#ifdef __NR_newfstatat
    __NR_newfstatat,          //
#endif
    __NR_openat | READONLY,      //
    __NR_read,                   //
    __NR_close,                  //
};

static const uint16_t kPledgeTty[] = {
    __NR_ioctl,  //
};

static const uint16_t kPledgeRecvfd[] = {
    __NR_recvmsg,   //
    __NR_recvmmsg,  //
};

static const uint16_t kPledgeSendfd[] = {
    __NR_sendmsg,   //
    __NR_sendmmsg,  //
};

static const uint16_t kPledgeProc[] = {
#ifdef __NR_fork
    __NR_fork,                    //
#endif
#ifdef __NR_vfork
    __NR_vfork,                   //
#endif
    __NR_clone | RESTRICT,        //
    __NR_kill,                    //
    __NR_tgkill,                  //
    __NR_setsid,                  //
    __NR_setpgid,                 //
    __NR_prlimit64,               //
    __NR_setrlimit,               //
    __NR_getpriority,             //
    __NR_setpriority,             //
    __NR_ioprio_get,              //
    __NR_ioprio_set,              //
    __NR_sched_getscheduler,      //
    __NR_sched_setscheduler,      //
    __NR_sched_get_priority_min,  //
    __NR_sched_get_priority_max,  //
    __NR_sched_getparam,          //
    __NR_sched_setparam,          //
};

static const uint16_t kPledgeId[] = {
    __NR_setuid,       //
    __NR_setreuid,     //
    __NR_setresuid,    //
    __NR_setgid,       //
    __NR_setregid,     //
    __NR_setresgid,    //
    __NR_setgroups,    //
    __NR_prlimit64,    //
    __NR_setrlimit,    //
    __NR_getpriority,  //
    __NR_setpriority,  //
    __NR_setfsuid,     //
    __NR_setfsgid,     //
};

static const uint16_t kPledgeChown[] = {
#ifdef __NR_chown
    __NR_chown,     //
#endif
    __NR_fchown,    //
#ifdef __NR_lchown
    __NR_lchown,    //
#endif
    __NR_fchownat,  //
};

static const uint16_t kPledgeSettime[] = {
    __NR_settimeofday,   //
    __NR_clock_adjtime,  //
};

static const uint16_t kPledgeProtExec[] = {
    __NR_mmap | EXEC,  //
    __NR_mprotect,     //
};

static const uint16_t kPledgeExec[] = {
    __NR_execve,    //
    __NR_execveat,  //
};

static const uint16_t kPledgeUnveil[] = {
    __NR_landlock_create_ruleset,  //
    __NR_landlock_add_rule,        //
    __NR_landlock_restrict_self,   //
};

// placeholder group
//
// pledge.com checks this to do auto-unveiling
static const uint16_t kPledgeVminfo[] = {
    __NR_sched_yield,  //
};

// placeholder group
//
// pledge.com uses this to auto-unveil /tmp and $TMPPATH with rwc
// permissions. pledge() alone (without unveil() too) offers very
// little security here. consider using them together.
static const uint16_t kPledgeTmppath[] = {
#ifdef __NR_lstat
    __NR_lstat,     //
#endif
#ifdef __NR_unlink
    __NR_unlink,    //
#endif
    __NR_unlinkat,  //
};

const struct Pledges kPledge[PROMISE_LEN_] = {
    [PROMISE_STDIO] = {"stdio", PLEDGE(kPledgeStdio)},             //
    [PROMISE_RPATH] = {"rpath", PLEDGE(kPledgeRpath)},             //
    [PROMISE_WPATH] = {"wpath", PLEDGE(kPledgeWpath)},             //
    [PROMISE_CPATH] = {"cpath", PLEDGE(kPledgeCpath)},             //
    [PROMISE_DPATH] = {"dpath", PLEDGE(kPledgeDpath)},             //
    [PROMISE_FLOCK] = {"flock", PLEDGE(kPledgeFlock)},             //
    [PROMISE_FATTR] = {"fattr", PLEDGE(kPledgeFattr)},             //
    [PROMISE_INET] = {"inet", PLEDGE(kPledgeInet)},                //
    [PROMISE_UNIX] = {"unix", PLEDGE(kPledgeUnix)},                //
    [PROMISE_DNS] = {"dns", PLEDGE(kPledgeDns)},                   //
    [PROMISE_TTY] = {"tty", PLEDGE(kPledgeTty)},                   //
    [PROMISE_RECVFD] = {"recvfd", PLEDGE(kPledgeRecvfd)},          //
    [PROMISE_SENDFD] = {"sendfd", PLEDGE(kPledgeSendfd)},          //
    [PROMISE_PROC] = {"proc", PLEDGE(kPledgeProc)},                //
    [PROMISE_EXEC] = {"exec", PLEDGE(kPledgeExec)},                //
    [PROMISE_ID] = {"id", PLEDGE(kPledgeId)},                      //
    [PROMISE_UNVEIL] = {"unveil", PLEDGE(kPledgeUnveil)},          //
    [PROMISE_SETTIME] = {"settime", PLEDGE(kPledgeSettime)},       //
    [PROMISE_PROT_EXEC] = {"prot_exec", PLEDGE(kPledgeProtExec)},  //
    [PROMISE_VMINFO] = {"vminfo", PLEDGE(kPledgeVminfo)},          //
    [PROMISE_TMPPATH] = {"tmppath", PLEDGE(kPledgeTmppath)},       //
    [PROMISE_CHOWN] = {"chown", PLEDGE(kPledgeChown)},             //
};

static int FindPromise(const char *name) {
  int i;
  for (i = 0; i < ARRAYLEN(kPledge); ++i) {
    if (!strcasecmp(name, kPledge[i].name)) {
      return i;
    }
  }
  return -1;
}

/**
 * Parses the arguments to pledge() into a bitmask.
 *
 * @return 0 on success, or -1 if invalid
 */
int ParsePromises(const char *promises, unsigned long *out) {
  int rc = 0;
  int promise;
  unsigned long ipromises;
  char *tok, *state, *start, buf[256];
  if (promises) {
    ipromises = -1;
    if (memccpy(buf, promises, 0, sizeof(buf))) {
      start = buf;
      while ((tok = strtok_r(start, " \t\r\n", &state))) {
        if ((promise = FindPromise(tok)) != -1) {
          ipromises &= ~(1ULL << promise);
        } else {
          rc = -1;
          break;
        }
        start = 0;
      }
    } else {
      rc = -1;
    }
  } else {
    ipromises = 0;
  }
  if (!rc) {
    *out = ipromises;
  }
  return rc;
}

#define PLEDGE_PENALTY_KILL_THREAD  0x0000
#define PLEDGE_PENALTY_KILL_PROCESS 0x0001
#define PLEDGE_PENALTY_RETURN_EPERM 0x0002
#define PLEDGE_PENALTY_MASK         0x000f
#define PLEDGE_STDERR_LOGGING       0x0010

#define ksnprintf snprintf

#endif

#define USAGE \
  "\
usage: pledge.com [-hnN] PROG ARGS...\n\
  -h              show help\n\
  -g GID          call setgid()\n\
  -u UID          call setuid()\n\
  -c PATH         call chroot()\n\
  -v [PERM:]PATH  call unveil(PATH, PERM[rwxc])\n\
  -V              disable unveiling (only pledge)\n\
  -q              disable stderr violation logging\n\
  -k              kill process rather than eperm'ing\n\
  -n              set maximum niceness\n\
  -D              don't drop capabilities\n\
  -N              don't normalize file descriptors\n\
  -C SECS         set cpu limit [default: inherited]\n\
  -M BYTES        set virtual memory limit [default: 4gb]\n\
  -O FILES        set file descriptor limit [default: 64]\n\
  -P PROCS        set process limit [default: preexisting + cpus]\n\
  -F BYTES        set individual file size limit [default: 4gb]\n\
  -T pledge       exits 0 if pledge() is supported by host system\n\
  -T unveil       exits 0 if unveil() is supported by host system\n\
  -p PLEDGE       may contain any of following separated by spaces\n\
     - stdio: allow stdio and benign system calls\n\
     - rpath: read-only path ops\n\
     - wpath: write path ops\n\
     - cpath: create path ops\n\
     - dpath: create special files\n\
     - chown: allows file ownership changes\n\
     - flock: file locks\n\
     - tty: terminal ioctls\n\
     - recvfd: allow SCM_RIGHTS\n\
     - sendfd: allow SCM_RIGHTS\n\
     - fattr: allow changing some struct stat bits\n\
     - inet: allow IPv4 and IPv6\n\
     - unix: allow local sockets\n\
     - id: allow setuid and friends\n\
     - dns: allow dns and related files\n\
     - proc: allow process and thread creation\n\
     - exec: implied by default\n\
     - prot_exec: allow creating executable memory\n\
     - vminfo: allows /proc/stat, /proc/self/maps, etc.\n\
     - tmppath: allows /tmp, $TMPPATH, lstat, unlink\n\
\n\
pledge.com v1.8\n\
copyright 2022 justine alexandra roberts tunney\n\
notice licenses are embedded in the binary\n\
https://twitter.com/justinetunney\n\
https://linkedin.com/in/jtunney\n\
https://justine.lol/pledge/\n\
https://github.com/jart\n\
\n\
this program lets you launch linux commands in a sandbox that's\n\
inspired by the design of openbsd's pledge() system call. Visit\n\
the https://justine.lol/pledge/ page for online documentation.\n\
\n\
"

int g_gflag;
int g_uflag;
int g_kflag;
int g_hflag;
bool g_nice;
bool g_qflag;
bool isdynamic;
bool g_noclose;
long g_cpuquota;
long g_fszquota;
long g_nfdquota;
long g_memquota;
long g_proquota;
long g_dontdrop;
long g_dontunveil;
const char *g_test;
const char *g_chroot;
const char *g_promises;
char dsopath[PATH_MAX];
char tmppath[PATH_MAX];

struct {
  int n;
  char **p;
} unveils;

static void GetOpts(int argc, char *argv[]) {
  int opt;
  struct sysinfo si;
  g_promises = 0;
  g_nfdquota = 64;
  g_fszquota = 256 * 1000 * 1000;
  if (!sysinfo(&si)) {
    g_memquota = si.totalram;
    g_proquota = _getcpucount() + si.procs;
  } else {
    g_proquota = _getcpucount() * 100;
    g_memquota = 4L * 1024 * 1024 * 1024;
  }
  while ((opt = getopt(argc, argv, "hnqkNVT:p:u:g:c:C:D:P:M:F:O:v:")) != -1) {
    switch (opt) {
      case 'n':
        g_nice = true;
        break;
      case 'q':
        g_qflag = true;
        break;
      case 'k':
        g_kflag = true;
        break;
      case 'N':
        g_noclose = true;
        break;
      case 'D':
        g_dontdrop = true;
        break;
      case 'V':
        g_dontunveil = true;
        break;
      case 'T':
        g_test = optarg;
        break;
      case 'c':
        g_chroot = optarg;
        break;
      case 'g':
        g_gflag = atoi(optarg);
        break;
      case 'u':
        g_uflag = atoi(optarg);
        break;
      case 'C':
        g_cpuquota = atoi(optarg);
        break;
      case 'P':
        g_proquota = atoi(optarg);
        break;
      case 'O':
        g_nfdquota = atoi(optarg);
        break;
      case 'F':
        errno = 0;
        g_fszquota = sizetol(optarg, 1000);
        if (errno) {
          kprintf("error: invalid size: -F %s\n", optarg);
          exit(1);
        }
        break;
      case 'M':
        errno = 0;
        g_memquota = sizetol(optarg, 1024);
        if (errno) {
          kprintf("error: invalid size: -F %s\n", optarg);
          exit(1);
        }
        break;
      case 'p':
        if (g_promises) {
          g_promises = xstrcat(g_promises, ' ', optarg, NULL);
        } else {
          g_promises = optarg;
        }
        break;
      case 'v':
        unveils.p = realloc(unveils.p, ++unveils.n * sizeof(*unveils.p));
        unveils.p[unveils.n - 1] = optarg;
        break;
      case 'h':
      case '?':
        write(1, USAGE, sizeof(USAGE) - 1);
        exit(0);
      default:
        write(2, USAGE, sizeof(USAGE) - 1);
        exit(64);
    }
  }
  if (!g_promises) {
    g_promises = "stdio rpath";
  }
}

const char *prog;
char pathbuf[PATH_MAX];
struct pollfd pfds[256];

static bool SupportsLandlock(void) {
  int e = errno;
  bool r = landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION) >= 0;
  errno = e;
  return r;
}

int GetPollMaxFds(void) {
  int n;
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != -1) {
    n = rl.rlim_cur;
  } else {
    n = 64;
  }
  return MIN(ARRAYLEN(pfds), MAX(3, n));
}

void NormalizeFileDescriptors(void) {
  int e, i, n, fd;
  n = GetPollMaxFds();
  e = errno;
  closefrom(3);  // more secure if linux 5.9+
  errno = e;
  for (i = 0; i < n; ++i) {
    pfds[i].fd = i;
    pfds[i].events = POLLIN;
  }
  if (poll(pfds, n, 0) == -1) {
    kprintf("error: poll() failed: %m\n");
    exit(1);
  }
  for (i = 0; i < 3; ++i) {
    if (pfds[i].revents & POLLNVAL) {
      if ((fd = open("/dev/null", O_RDWR)) == -1) {
        kprintf("error: open(\"/dev/null\") failed: %m\n");
        exit(2);
      }
      if (fd != i) {
        kprintf("error: open() is broken: %d vs. %d\n", fd, i);
        exit(3);
      }
    }
  }
  for (i = 3; i < n; ++i) {
    if (~pfds[i].revents & POLLNVAL) {
      if (close(pfds[i].fd) == -1) {
        kprintf("error: close(%d) failed: %m\n", pfds[i].fd);
        exit(4);
      }
    }
  }
}

int SetLimit(int r, long lo, long hi) {
  struct rlimit old;
  struct rlimit lim = {lo, hi};
  if (r < 0 || r >= RLIM_NLIMITS) return 0;
  if (!setrlimit(r, &lim)) return 0;
  if (getrlimit(r, &old)) return -1;
  lim.rlim_cur = MIN(lim.rlim_cur, old.rlim_max);
  lim.rlim_max = MIN(lim.rlim_max, old.rlim_max);
  return setrlimit(r, &lim);
}

int GetBaseCpuFreqMhz(void) {
  return 0;//KCPUIDS(16H, EAX) & 0x7fff;
}

int SetCpuLimit(int secs) {
  int mhz, lim;
  if (secs <= 0) return 0;
  if (!(mhz = GetBaseCpuFreqMhz())) {
    errno = EOPNOTSUPP;
    return -1;
  }
  lim = ceil(3100. / mhz * secs);
  return SetLimit(RLIMIT_CPU, lim, lim);
}

bool PathExists(const char *path) {
  int err;
  struct stat st;
  if (path) {
    err = errno;
    if (!stat(path, &st)) {
      return true;
    } else {
      errno = err;
      return false;
    }
  } else {
    return false;
  }
}

void Unveil(const char *path, const char *perm) {
  if (unveil(path, perm) == -1) {
    kprintf("error: unveil(%#s, %#s) failed: %m\n", path, perm);
    _Exit(20);
  }
}

int UnveilIfExists(const char *path, const char *perm) {
  int err;
  if (path) {
    err = errno;
    if (unveil(path, perm) != -1) {
      return 0;
    } else if (errno == ENOENT) {
      errno = err;
    } else {
      kprintf("error: unveil(%#s, %#s) failed: %m\n", path, perm);
      _Exit(20);
    }
  }
  return -1;
}

void MakeProcessNice(void) {
  if (!g_nice) return;
  if (setpriority(PRIO_PROCESS, 0, 19) == -1) {
    kprintf("error: setpriority(PRIO_PROCESS, 0, 19) failed: %m\n");
    exit(23);
  }
  int rc = syscall(__NR_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                      IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0));
  if (rc < 0) {
    errno = -rc;
    kprintf("error: ioprio_set() failed: %m\n");
    exit(23);
  }
  struct sched_param p = {sched_get_priority_min(SCHED_IDLE)};
  if (sched_setscheduler(0, SCHED_IDLE, &p) == -1) {
    kprintf("error: sched_setscheduler(SCHED_IDLE) failed: %m\n");
    exit(23);
  }
}

void ApplyFilesystemPolicy(unsigned long ipromises) {
  const char *p;

  if (g_dontunveil) return;
  if (!SupportsLandlock()) return;

  Unveil(prog, "rx");

  if (true) {
    //Unveil(dsopath, "rx");
    UnveilIfExists("/lib", "rx");
    UnveilIfExists("/lib64", "rx");
    UnveilIfExists("/usr/lib", "rx");
    UnveilIfExists("/usr/lib64", "rx");
    UnveilIfExists("/usr/local/lib", "rx");
    UnveilIfExists("/usr/local/lib64", "rx");
    UnveilIfExists("/etc/ld-musl-x86_64.path", "r");
    UnveilIfExists("/etc/ld.so.conf", "r");
    UnveilIfExists("/etc/ld.so.cache", "r");
    UnveilIfExists("/etc/ld.so.conf.d", "r");
    UnveilIfExists("/etc/ld.so.preload", "r");
  }

  if (~ipromises & (1ul << PROMISE_STDIO)) {
    UnveilIfExists("/dev/fd", "r");
    UnveilIfExists("/dev/log", "w");
    UnveilIfExists("/dev/zero", "r");
    UnveilIfExists("/dev/null", "rw");
    UnveilIfExists("/dev/full", "rw");
    UnveilIfExists("/dev/stdin", "rw");
    UnveilIfExists("/dev/stdout", "rw");
    UnveilIfExists("/dev/stderr", "rw");
    UnveilIfExists("/dev/urandom", "r");
    UnveilIfExists("/etc/localtime", "r");
    UnveilIfExists("/proc/self/fd", "rw");
    UnveilIfExists("/proc/self/stat", "r");
    UnveilIfExists("/proc/self/status", "r");
    UnveilIfExists("/usr/share/locale", "r");
    UnveilIfExists("/proc/self/cmdline", "r");
    UnveilIfExists("/usr/share/zoneinfo", "r");
    UnveilIfExists("/proc/sys/kernel/version", "r");
    UnveilIfExists("/usr/share/common-licenses", "r");
    UnveilIfExists("/proc/sys/kernel/ngroups_max", "r");
    UnveilIfExists("/proc/sys/kernel/cap_last_cap", "r");
    UnveilIfExists("/proc/sys/vm/overcommit_memory", "r");
  }

  if (~ipromises & (1ul << PROMISE_INET)) {
    UnveilIfExists("/etc/ssl/certs/ca-certificates.crt", "r");
  }

  if (~ipromises & (1ul << PROMISE_RPATH)) {
    UnveilIfExists("/proc/filesystems", "r");
  }

  if (~ipromises & (1ul << PROMISE_DNS)) {
    UnveilIfExists("/etc/hosts", "r");
    UnveilIfExists("/etc/hostname", "r");
    UnveilIfExists("/etc/services", "r");
    UnveilIfExists("/etc/protocols", "r");
    UnveilIfExists("/etc/resolv.conf", "r");
  }

  if (~ipromises & (1ul << PROMISE_TTY)) {
    UnveilIfExists(ttyname(0), "rw");
    UnveilIfExists("/dev/tty", "rw");
    UnveilIfExists("/dev/console", "rw");
    UnveilIfExists("/etc/terminfo", "r");
    UnveilIfExists("/usr/lib/terminfo", "r");
    UnveilIfExists("/usr/share/terminfo", "r");
  }

  if (~ipromises & (1ul << PROMISE_PROT_EXEC)) {
    if (UnveilIfExists("/usr/bin/ape", "rx") == -1) {
      if ((p = getenv("TMPDIR"))) {
        UnveilIfExists(xjoinpaths(p, ".ape"), "rx");
      }
      if ((p = getenv("HOME"))) {
        UnveilIfExists(xjoinpaths(p, ".ape"), "rx");
      }
    }
  }

  if (~ipromises & (1ul << PROMISE_VMINFO)) {
    UnveilIfExists("/proc/stat", "r");
    UnveilIfExists("/proc/meminfo", "r");
    UnveilIfExists("/proc/cpuinfo", "r");
    UnveilIfExists("/proc/diskstats", "r");
    UnveilIfExists("/proc/self/maps", "r");
    UnveilIfExists("/sys/devices/system/cpu", "r");
  }

  if (~ipromises & (1ul << PROMISE_TMPPATH)) {
    UnveilIfExists("/tmp", "rwc");
    UnveilIfExists(getenv("TMPPATH"), "rwc");
  }

  for (int i = 0; i < unveils.n; ++i) {
    char *s, *t;
    const char *path;
    const char *perm;
    s = unveils.p[i];
    if ((t = strchr(s, ':'))) {
      *t = 0;
      perm = s;
      path = t + 1;
    } else {
      perm = "r";
      path = s;
    }
    UnveilIfExists(path, perm);
  }

  if (unveil(0, 0) == -1) {
    kprintf("error: unveil(0, 0) failed: %m\n");
    _Exit(20);
  }
}

void DropCapabilities(void) {
  int e, i;
  for (e = errno, i = 0;; ++i) {
    if (prctl(PR_CAPBSET_DROP, i) == -1) {
      if (errno == EINVAL || errno == EPERM) {
        errno = e;
        break;
      } else {
        kprintf("error: prctl(PR_CAPBSET_DROP, %d) failed: %m\n", i);
        _Exit(25);
      }
    }
  }
}

bool FileExistsAndIsNewerThan(const char *filepath, const char *thanpath) {
  struct stat st1, st2;
  if (stat(filepath, &st1) == -1) return false;
  if (stat(thanpath, &st2) == -1) return false;
  if (st1.st_mtim.tv_sec < st2.st_mtim.tv_sec) return false;
  if (st1.st_mtim.tv_sec > st2.st_mtim.tv_sec) return true;
  return st1.st_mtim.tv_nsec >= st2.st_mtim.tv_nsec;
}

int __pledge_mode;

unsigned long __promises;
unsigned long __execpromises;

struct Filter {
  size_t n;
  struct sock_filter p[700];
};

#define privileged
#define notpossible abort()

static privileged void *MemCpy(void *d, const void *s, unsigned long n) {
  unsigned long i = 0;
  for (; i < n; ++i) ((char *)d)[i] = ((char *)s)[i];
  return (char *)d + n;
}

static privileged void AppendFilter(struct Filter *f, struct sock_filter *p,
                                    size_t n) {
  if (UNLIKELY(f->n + n > ARRAYLEN(f->p))) notpossible;
  MemCpy(f->p + f->n, p, n * sizeof(*f->p));
  f->n += n;
}


static struct sock_filter kPledgeStart[] = {
    // make sure this isn't an i386 binary or something
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(arch)),
//    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
//    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    // each filter assumes ordinal is already loaded into accumulator
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
    // forbid some system calls with ENOSYS (rather than EPERM)
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __NR_memfd_secret, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rseq, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_memfd_create, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
};

static struct sock_filter kFilterIgnoreExitGroup[] = {
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
};

// The first argument of kill() must be
//
//   - getpid()
//
static privileged void AllowKillSelf(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first argument of tgkill() must be
//
//   - getpid()
//
static privileged void AllowTgkillSelf(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The following system calls are allowed:
//
//   - write(2) to allow logging
//   - kill(getpid(), SIGABRT) to abort process
//   - tkill(gettid(), SIGABRT) to abort thread
//   - sigaction(SIGABRT) to force default signal handler
//   - sigreturn() to return from signal handler
//   - sigprocmask() to force signal delivery
//
static privileged void AllowMonitor(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 6),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tkill, 0, 6),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, gettid(), 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGABRT, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first argument of sys_clone_linux() must NOT have:
//
//   - CLONE_NEWNS    (0x00020000)
//   - CLONE_PTRACE   (0x00002000)
//   - CLONE_UNTRACED (0x00800000)
//
static privileged void AllowCloneRestrict(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00822000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first argument of sys_clone_linux() must have:
//
//   - CLONE_VM       (0x00000100)
//   - CLONE_FS       (0x00000200)
//   - CLONE_FILES    (0x00000400)
//   - CLONE_THREAD   (0x00010000)
//   - CLONE_SIGHAND  (0x00000800)
//
// The first argument of sys_clone_linux() must NOT have:
//
//   - CLONE_NEWNS    (0x00020000)
//   - CLONE_PTRACE   (0x00002000)
//   - CLONE_UNTRACED (0x00800000)
//
static privileged void AllowCloneThread(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00010f00),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x00010f00, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00822000),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - FIONREAD (0x541b)
//   - FIONBIO  (0x5421)
//   - FIOCLEX  (0x5451)
//   - FIONCLEX (0x5450)
//
static privileged void AllowIoctlStdio(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 7),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONREAD, 3, 0),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONBIO, 2, 0),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIOCLEX, 1, 0),
      /*L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONCLEX, 0, 1),
      /*L6*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L8*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - SIOCATMARK (0x8905)
//
static privileged void AllowIoctlInet(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIOCATMARK, 0, 1),
      /*L6*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L8*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - TCGETS     (0x5401)
//   - TCSETS     (0x5402)
//   - TCSETSW    (0x5403)
//   - TCSETSF    (0x5404)
//   - TIOCGWINSZ (0x5413)
//   - TIOCSPGRP  (0x5410)
//   - TIOCGPGRP  (0x540f)
//   - TIOCSWINSZ (0x5414)
//   - TCFLSH     (0x540b)
//   - TCXONC     (0x540a)
//   - TCSBRK     (0x5409)
//   - TIOCSBRK   (0x5427)
//
static privileged void AllowIoctlTty(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 15),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 11, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCSETS, 10, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCSETSW, 9, 0),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCSETSF, 8, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCGWINSZ, 7, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSPGRP, 6, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCGPGRP, 5, 0),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSWINSZ, 4, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCFLSH, 3, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCXONC, 2, 0),
      /*L12*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCSBRK, 1, 0),
      /*L13*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSBRK, 0, 1),
      /*L14*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L15*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L16*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The level argument of setsockopt() must be one of:
//
//   - SOL_IP     (0)
//   - SOL_SOCKET (1)
//   - SOL_TCP    (6)
//   - SOL_IPV6   (41)
//
// The optname argument of setsockopt() must be one of:
//
//   - TCP_NODELAY          (0x01)
//   - TCP_CORK             (0x03)
//   - TCP_KEEPIDLE         (0x04)
//   - TCP_KEEPINTVL        (0x05)
//   - SO_TYPE              (0x03)
//   - SO_ERROR             (0x04)
//   - SO_DONTROUTE         (0x05)
//   - SO_BROADCAST         (0x06)
//   - SO_REUSEPORT         (0x0f)
//   - SO_REUSEADDR         (0x02)
//   - SO_KEEPALIVE         (0x09)
//   - SO_RCVTIMEO          (0x14)
//   - SO_SNDTIMEO          (0x15)
//   - IP_RECVTTL           (0x0c)
//   - IP_RECVERR           (0x0b)
//   - TCP_FASTOPEN         (0x17)
//   - TCP_FASTOPEN_CONNECT (0x1e)
//   - IPV6_V6ONLY          (0x1a)
//   - TCP_QUICKACK         (0x0c)
//
static privileged void AllowSetsockoptRestrict(struct Filter *f) {
  static struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 25),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 41, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 19),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0c, 16, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x1a, 15, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 14, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0f, 13, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x03, 12, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0c, 11, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x13, 10, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 9, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x09, 8, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x14, 7, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 6, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0b, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x04, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x05, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x17, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x1e, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x15, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The level argument of getsockopt() must be one of:
//
//   - SOL_SOCKET (1)
//   - SOL_TCP    (6)
//
// The optname argument of getsockopt() must be one of:
//
//   - SO_TYPE      (0x03)
//   - SO_ERROR     (0x04)
//   - SO_REUSEPORT (0x0f)
//   - SO_REUSEADDR (0x02)
//   - SO_KEEPALIVE (0x09)
//   - SO_RCVTIMEO  (0x14)
//   - SO_SNDTIMEO  (0x15)
//
static privileged void AllowGetsockoptRestrict(struct Filter *f) {
  static const int nr = __NR_getsockopt;
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 13),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 9),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x03, 6, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x04, 5, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0f, 4, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 3, 0),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x09, 2, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x14, 1, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x15, 0, 1),
      /*L12*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L13*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L14*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The flags parameter of mmap() must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
static privileged void AllowMmapExec(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),  // flags
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x52000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5 - 4),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The prot parameter of mmap() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
// The flags parameter must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_POPULATE (0x08000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
static privileged void AllowMmapNoexec(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),  // prot
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(PROT_READ | PROT_WRITE)),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),  // flags
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x5a000),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The prot parameter of mprotect() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
static privileged void AllowMprotectNoexec(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),  // prot
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(PROT_READ | PROT_WRITE)),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_RDONLY
//
// The flags parameter of open() must not have:
//
//   - O_CREAT     (000000100)
//   - O_TRUNC     (000001000)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenReadonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020001100),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_RDONLY
//
// The flags parameter of open() must not have:
//
//   - O_CREAT     (000000100)
//   - O_TRUNC     (000001000)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenatReadonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020001100),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_WRONLY
//   - (flags & O_ACCMODE) == O_RDWR
//
// The open() flags parameter must not contain
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenWriteonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 10 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 1, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 9 - 5),
      /* L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L6*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020000100),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L8*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* L9*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L10*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_WRONLY
//   - (flags & O_ACCMODE) == O_RDWR
//
// The openat() flags parameter must not contain
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenatWriteonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 10 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 1, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 9 - 5),
      /* L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L6*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020000100),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L8*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* L9*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L10*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// If the flags parameter of open() has one of:
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowOpenCreatonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 12 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 000000100),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 000000100, 7 - 4, 0),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020200000),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 020200000, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L8*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L10*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L11*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L12*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// If the flags parameter of openat() has one of:
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowOpenatCreatonly(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 12 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 000000100),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 000000100, 7 - 4, 0),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020200000),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 020200000, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),
      /* L8*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L10*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L11*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L12*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_creat
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowCreatRestrict(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The second argument of fcntl() must be one of:
//
//   - F_DUPFD (0)
//   - F_DUPFD_CLOEXEC (1030)
//   - F_GETFD (1)
//   - F_SETFD (2)
//   - F_GETFL (3)
//   - F_SETFL (4)
//
static privileged void AllowFcntlStdio(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1030, 4 - 3, 0),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 5, 5 - 4, 0),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of fcntl() must be one of:
//
//   - F_GETLK (0x05)
//   - F_SETLK (0x06)
//   - F_SETLKW (0x07)
//   - F_OFD_GETLK (0x24)
//   - F_OFD_SETLK (0x25)
//   - F_OFD_SETLKW (0x26)
//
static privileged void AllowFcntlLock(struct Filter *f) {
  static struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 9),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x05, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x07, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x24, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x25, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x26, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The addr parameter of sendto() must be
//
//   - NULL
//
static privileged void AllowSendtoAddrless(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 7 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[4]) + 0),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 3),
      /*L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[4]) + 4),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 5),
      /*L5*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L6*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L7*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The family parameter of socket() must be one of:
//
//   - AF_INET  (0x02)
//   - AF_INET6 (0x0a)
//
// The type parameter of socket() will ignore:
//
//   - SOCK_CLOEXEC  (0x80000)
//   - SOCK_NONBLOCK (0x00800)
//
// The type parameter of socket() must be one of:
//
//   - SOCK_STREAM (0x01)
//   - SOCK_DGRAM  (0x02)
//
// The protocol parameter of socket() must be one of:
//
//   - 0
//   - IPPROTO_ICMP (0x01)
//   - IPPROTO_TCP  (0x06)
//   - IPPROTO_UDP  (0x11)
//
static privileged void AllowSocketInet(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 15 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 1, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0a, 0, 14 - 4),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 1, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 0, 14 - 8),
      /* L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x00, 3, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 2, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 1, 0),
      /*L12*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 1),
      /*L13*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L14*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L15*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The family parameter of socket() must be one of:
//
//   - AF_UNIX (1)
//   - AF_LOCAL (1)
//
// The type parameter of socket() will ignore:
//
//   - SOCK_CLOEXEC  (0x80000)
//   - SOCK_NONBLOCK (0x00800)
//
// The type parameter of socket() must be one of:
//
//   - SOCK_STREAM (1)
//   - SOCK_DGRAM  (2)
//
// The protocol parameter of socket() must be one of:
//
//   - 0
//
static privileged void AllowSocketUnix(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 11 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 10 - 3),
      /* L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L9*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L10*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L11*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first parameter of prctl() can be any of
//
//   - PR_SET_NAME         (15)
//   - PR_GET_NAME         (16)
//   - PR_GET_SECCOMP      (21)
//   - PR_SET_SECCOMP      (22)
//   - PR_SET_NO_NEW_PRIVS (38)
//   - PR_CAPBSET_READ     (23)
//   - PR_CAPBSET_DROP     (24)
//
static privileged void AllowPrctlStdio(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 11 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 15, 6, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 16, 5, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 21, 4, 0),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 3, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 23, 2, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 24, 1, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 38, 0, 1),
      /* L9*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L10*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L11*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_chmod
// The mode parameter of chmod() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowChmodNobits(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chmod, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The mode parameter of fchmod() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowFchmodNobits(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmod, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The mode parameter of fchmodat() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowFchmodatNobits(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmodat, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The new_limit parameter of prlimit() must be
//
//   - NULL (0)
//
static privileged void AllowPrlimitStdio(struct Filter *f) {
  static struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prlimit64, 0, 7 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 3),
      /*L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2]) + 4),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L5*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L6*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L7*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

static privileged int CountUnspecial(const uint16_t *p, size_t len) {
  int i, count;
  for (count = i = 0; i < len; ++i) {
    if (!(p[i] & SPECIAL)) {
      ++count;
    }
  }
  return count;
}

static privileged void AppendPledge(struct Filter *f,   //
                                    const uint16_t *p,  //
                                    size_t len) {       //
  int i, j, count;

  // handle ordinals which allow syscalls regardless of args
  // we put in extra effort here to reduce num of bpf instrs
  if ((count = CountUnspecial(p, len))) {
    if (count < 256) {
      for (j = i = 0; i < len; ++i) {
        if (p[i] & SPECIAL) continue;
        // jump to ALLOW rule below if accumulator equals ordinal
        struct sock_filter fragment[] = {
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,  // instruction
                     p[i],                       // operand
                     count - j - 1,              // jump if true displacement
                     j == count - 1),            // jump if false displacement
        };
        AppendFilter(f, PLEDGE(fragment));
        ++j;
      }
      struct sock_filter fragment[] = {
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      };
      AppendFilter(f, PLEDGE(fragment));
    } else {
      notpossible;
    }
  }

  // handle "special" ordinals which use hand-crafted bpf
  for (i = 0; i < len; ++i) {
    if (!(p[i] & SPECIAL)) continue;
    switch (p[i]) {
      case __NR_mmap | EXEC:
        AllowMmapExec(f);
        break;
      case __NR_mmap | NOEXEC:
        AllowMmapNoexec(f);
        break;
      case __NR_mprotect | NOEXEC:
        AllowMprotectNoexec(f);
        break;
#ifdef __NR_chmod
      case __NR_chmod | NOBITS:
        AllowChmodNobits(f);
        break;
#endif
      case __NR_fchmod | NOBITS:
        AllowFchmodNobits(f);
        break;
      case __NR_fchmodat | NOBITS:
        AllowFchmodatNobits(f);
        break;
      case __NR_prctl | STDIO:
        AllowPrctlStdio(f);
        break;
#ifdef __NR_open
      case __NR_open | CREATONLY:
        AllowOpenCreatonly(f);
        break;
#endif
      case __NR_openat | CREATONLY:
        AllowOpenatCreatonly(f);
        break;
#ifdef __NR_open
      case __NR_open | READONLY:
        AllowOpenReadonly(f);
        break;
#endif
      case __NR_openat | READONLY:
        AllowOpenatReadonly(f);
        break;
#ifdef __NR_open
      case __NR_open | WRITEONLY:
        AllowOpenWriteonly(f);
        break;
#endif
      case __NR_openat | WRITEONLY:
        AllowOpenatWriteonly(f);
        break;
      case __NR_setsockopt | RESTRICT:
        AllowSetsockoptRestrict(f);
        break;
      case __NR_getsockopt | RESTRICT:
        AllowGetsockoptRestrict(f);
        break;
#ifdef __NR_creat
      case __NR_creat | RESTRICT:
        AllowCreatRestrict(f);
        break;
#endif
      case __NR_fcntl | STDIO:
        AllowFcntlStdio(f);
        break;
      case __NR_fcntl | LOCK:
        AllowFcntlLock(f);
        break;
      case __NR_ioctl | RESTRICT:
        AllowIoctlStdio(f);
        break;
      case __NR_ioctl | TTY:
        AllowIoctlTty(f);
        break;
      case __NR_ioctl | INET:
        AllowIoctlInet(f);
        break;
      case __NR_socket | INET:
        AllowSocketInet(f);
        break;
      case __NR_socket | UNIX:
        AllowSocketUnix(f);
        break;
      case __NR_sendto | ADDRLESS:
        AllowSendtoAddrless(f);
        break;
      case __NR_clone | RESTRICT:
        AllowCloneRestrict(f);
        break;
      case __NR_clone | THREAD:
        AllowCloneThread(f);
        break;
      case __NR_prlimit64 | STDIO:
        AllowPrlimitStdio(f);
        break;
      case __NR_kill | SELF:
        AllowKillSelf(f);
        break;
      case __NR_tgkill | SELF:
        AllowTgkillSelf(f);
        break;
      default:
        notpossible;
    }
  }
}

/**
 * Installs SECCOMP BPF filter on Linux thread.
 *
 * @param ipromises is inverted integer bitmask of pledge() promises
 * @return 0 on success, or negative error number on error
 * @asyncsignalsafe
 * @threadsafe
 * @vforksafe
 */
privileged int sys_pledge_linux(unsigned long ipromises, int mode) {
  struct Filter f;
  int i, e, rc = -1;
  struct sock_filter sf[1] = {BPF_STMT(BPF_RET | BPF_K, 0)};
  CheckLargeStackAllocation(&f, sizeof(f));
  f.n = 0;

  // set up the seccomp filter
  AppendFilter(&f, PLEDGE(kPledgeStart));
  if (ipromises == -1) {
    // if we're pledging empty string, then avoid triggering a sigsys
    // when _Exit() gets called since we need to fallback to _Exit1()
    AppendFilter(&f, PLEDGE(kFilterIgnoreExitGroup));
  }
  AppendPledge(&f, PLEDGE(kPledgeDefault));
  for (i = 0; i < ARRAYLEN(kPledge); ++i) {
    if (~ipromises & (1ul << i)) {
      if (kPledge[i].len) {
        AppendPledge(&f, kPledge[i].syscalls, kPledge[i].len);
      } else {
        notpossible;
      }
    }
  }

  // now determine what we'll do on sandbox violations
  if (mode & PLEDGE_STDERR_LOGGING) {
    // trapping mode
    //
    // if we haven't pledged exec, then we can monitor SIGSYS
    // and print a helpful error message when things do break
    // to avoid tls / static memory, we embed mode within bpf
    //MonitorSigSys();
    AllowMonitor(&f);
    sf[0].k = SECCOMP_RET_TRAP | (mode & SECCOMP_RET_DATA);
    AppendFilter(&f, PLEDGE(sf));
  } else {
    // non-trapping mode
    //
    // our sigsys error message handler can't be inherited across
    // execve() boundaries so if you've pledged exec then that'll
    // likely cause a SIGSYS in your child after the exec happens
    switch (mode & PLEDGE_PENALTY_MASK) {
      case PLEDGE_PENALTY_KILL_THREAD:
        sf[0].k = SECCOMP_RET_KILL_THREAD;
        break;
      case PLEDGE_PENALTY_KILL_PROCESS:
        sf[0].k = SECCOMP_RET_KILL_PROCESS;
        break;
      case PLEDGE_PENALTY_RETURN_EPERM:
        sf[0].k = SECCOMP_RET_ERRNO | EPERM;
        break;
      default:
        return -EINVAL;
    }
    AppendFilter(&f, PLEDGE(sf));
  }

  // drop privileges
  //
  // PR_SET_SECCOMP (Linux 2.6.23+) will refuse to work if
  // PR_SET_NO_NEW_PRIVS (Linux 3.5+) wasn't called so we punt the error
  // detection to the seccomp system call below.
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  // register our seccomp filter with the kernel
  struct sock_fprog sandbox = {.len = f.n, .filter = f.p};
  rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sandbox, 0, 0);

  // the EINVAL error could mean a lot of things. it could mean the bpf
  // code is broken. it could also mean we're running on RHEL5 which
  // doesn't have SECCOMP support. since we don't consider lack of
  // system support for security to be an error, we distinguish these
  // two cases by running a simpler SECCOMP operation.
  if (rc < 0 && errno == EINVAL && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) < 0 && errno == EINVAL) {
    rc = 0;  // -Enosys
  }

  return rc;
}

/**
 * Permits system operations, e.g.
 *
 *     __pledge_mode = PLEDGE_PENALTY_KILL_PROCESS | PLEDGE_STDERR_LOGGING;
 *     if (pledge("stdio rfile tty", 0)) {
 *       perror("pledge");
 *       exit(1);
 *     }
 *
 * Pledging causes most system calls to become unavailable. Your system
 * call policy is enforced by the kernel (which means it can propagate
 * across execve() if permitted). Root access is not required. Support
 * is limited to Linux 2.6.23+ (c. RHEL6) and OpenBSD. If your kernel
 * isn't supported, then pledge() will return 0 and do nothing rather
 * than raising ENOSYS. We don't consider lack of system support to be
 * an error, because the specified operations will be permitted.
 *
 * The promises you give pledge() define which system calls are allowed.
 * Error messages are logged when sandbox violations occur, but how that
 * happens depends on the `mode` parameter (see below).
 *
 * Timing is everything with pledge. It's designed to be a voluntary
 * self-imposed security model. That works best when programs perform
 * permission-hungry operations (e.g. calling GetSymbolTable) towards
 * the beginning of execution, and then relinquish privilege afterwards
 * by calling pledge(). Here's an example of where that matters. Your
 * Cosmopolitan C Library needs to code morph your executable in memory
 * once you start using threads. But that's only possible to do if you
 * used the `prot_exec` promise. So the right thing to do here, is to
 * call __enable_threads() before calling pledge() to force it early.
 *
 *     __enable_threads();
 *     ShowCrashReports();
 *     pledge("...", 0);
 *
 * By default exit() is allowed. This is useful for processes that
 * perform pure computation and interface with the parent via shared
 * memory. On Linux we mean sys_exit (_Exit1), not sys_exit_group
 * (_Exit). The difference is effectively meaningless, since _Exit()
 * will attempt both. All it means is that, if you're using threads,
 * then a `pledge("", 0)` thread can't kill all your threads unless you
 * `pledge("stdio", 0)`.
 *
 * Once pledge is in effect, the chmod functions (if allowed) will not
 * permit the sticky/setuid/setgid bits to change. Linux will EPERM here
 * and OpenBSD should ignore those three bits rather than crashing.
 *
 * User and group IDs can't be changed once pledge is in effect. OpenBSD
 * should ignore chown without crashing; whereas Linux will just EPERM.
 *
 * Using pledge is irreversible. On Linux it causes PR_SET_NO_NEW_PRIVS
 * to be set on your process; however, if "id" or "recvfd" are allowed
 * then then they theoretically could permit the gaining of some new
 * privileges. You may call pledge() multiple times if "stdio" is
 * allowed. In that case, the process can only move towards a more
 * restrictive state.
 *
 * pledge() can't filter filesystem paths. See unveil() which lets you
 * do that. pledge() also can't do address firewalling. For example if
 * you use the `inet` promise then your process will be able to talk to
 * *every* internet address including public ones.
 *
 * `promises` is a string that may include any of the following groups
 * delimited by spaces.
 *
 * - "stdio" allows exit, close, dup, dup2, dup3, fchdir, fstat, fsync,
 *   fdatasync, ftruncate, getdents, getegid, getrandom, geteuid,
 *   getgid, getgroups, times, getrusage, getitimer, getpgid, getpgrp,
 *   getpid, getppid, getresgid, getresuid, getrlimit, getsid, wait4,
 *   gettimeofday, getuid, lseek, madvise, brk, arch_prctl, uname,
 *   set_tid_address, clock_getres, clock_gettime, clock_nanosleep,
 *   mremap, mmap, (PROT_EXEC and weird flags aren't allowed), mprotect
 *   (PROT_EXEC isn't allowed), msync, sync_file_range, migrate_pages,
 *   munmap, nanosleep, pipe, pipe2, read, readv, pread, recv, poll,
 *   recvfrom, preadv, write, writev, pwrite, pwritev, select, pselect6,
 *   copy_file_range, sendfile, tee, splice, vmsplice, alarm, pause,
 *   send, sendto (only if addr is null), setitimer, shutdown, sigaction
 *   (but SIGSYS is forbidden), sigaltstack, sigprocmask, sigreturn,
 *   sigsuspend, umask, mincore, socketpair, ioctl(FIONREAD),
 *   ioctl(FIONBIO), ioctl(FIOCLEX), ioctl(FIONCLEX), fcntl(F_GETFD),
 *   fcntl(F_SETFD), fcntl(F_GETFL), fcntl(F_SETFL), sched_yield,
 *   epoll_create, epoll_create1, epoll_ctl, epoll_wait, epoll_pwait,
 *   epoll_pwait2, clone(CLONE_THREAD), futex, set_robust_list,
 *   get_robust_list, setaffinity, sigpending.
 *
 * - "rpath" (read-only path ops) allows chdir, getcwd, open(O_RDONLY),
 *   openat(O_RDONLY), stat, fstat, lstat, fstatat, access, faccessat,
 *   faccessat2, readlink, readlinkat, statfs, fstatfs.
 *
 * - "wpath" (write path ops) allows getcwd, open(O_WRONLY),
 *   openat(O_WRONLY), stat, fstat, lstat, fstatat, access, faccessat,
 *   faccessat2, readlink, readlinkat, chmod, fchmod, fchmodat.
 *
 * - "cpath" (create path ops) allows open(O_CREAT), openat(O_CREAT),
 *   rename, renameat, renameat2, link, linkat, symlink, symlinkat,
 *   unlink, rmdir, unlinkat, mkdir, mkdirat.
 *
 * - "dpath" (create special path ops) allows mknod, mknodat, mkfifo.
 *
 * - "flock" allows flock, fcntl(F_GETLK), fcntl(F_SETLK),
 *   fcntl(F_SETLKW).
 *
 * - "tty" allows ioctl(TIOCGWINSZ), ioctl(TCGETS), ioctl(TCSETS),
 *   ioctl(TCSETSW), ioctl(TCSETSF).
 *
 * - "recvfd" allows recvmsg and recvmmsg.
 *
 * - "recvfd" allows sendmsg and sendmmsg.
 *
 * - "fattr" allows chmod, fchmod, fchmodat, utime, utimes, futimens,
 *   utimensat.
 *
 * - "inet" allows socket(AF_INET), listen, bind, connect, accept,
 *   accept4, getpeername, getsockname, setsockopt, getsockopt, sendto.
 *
 * - "unix" allows socket(AF_UNIX), listen, bind, connect, accept,
 *   accept4, getpeername, getsockname, setsockopt, getsockopt.
 *
 * - "dns" allows socket(AF_INET), sendto, recvfrom, connect.
 *
 * - "proc" allows fork, vfork, clone, kill, tgkill, getpriority,
 *   setpriority, prlimit, setrlimit, setpgid, setsid.
 *
 * - "id" allows setuid, setreuid, setresuid, setgid, setregid,
 *   setresgid, setgroups, prlimit, setrlimit, getpriority, setpriority,
 *   setfsuid, setfsgid.
 *
 * - "settime" allows settimeofday and clock_adjtime.
 *
 * - "exec" allows execve, execveat. Note that `exec` alone might not be
 *   enough by itself to let your executable be executed. For dynamic,
 *   interpreted, and ape binaries, you'll usually want `rpath` and
 *   `prot_exec` too. With APE it's possible to work around this
 *   requirement, by "assimilating" your binaries beforehand. See the
 *   assimilate.com program and `--assimilate` flag which can be used to
 *   turn APE binaries into static native binaries.
 *
 * - "prot_exec" allows mmap(PROT_EXEC) and mprotect(PROT_EXEC). This is
 *   needed to (1) code morph mutexes in __enable_threads(), and it's
 *   needed to (2) launch non-static or non-native executables, e.g.
 *   non-assimilated APE binaries, or dynamic-linked executables.
 *
 * - "unveil" allows unveil() to be called, as well as the underlying
 *   landlock_create_ruleset, landlock_add_rule, landlock_restrict_self
 *   calls on Linux.
 *
 * - "vminfo" OpenBSD defines this for programs like `top`. On Linux,
 *   this is a placeholder group that lets tools like pledge.com check
 *   `__promises` and automatically unveil() a subset of files top would
 *   need, e.g. /proc/stat, /proc/meminfo.
 *
 * - "tmppath" allows unlink, unlinkat, and lstat. This is mostly a
 *   placeholder group for pledge.com, which reads the `__promises`
 *   global to determine if /tmp and $TMPPATH should be unveiled.
 *
 * `execpromises` only matters if "exec" is specified in `promises`. In
 * that case, this specifies the promises that'll apply once execve()
 * happens. If this is NULL then the default is used, which is
 * unrestricted. OpenBSD allows child processes to escape the sandbox
 * (so a pledged OpenSSH server process can do things like spawn a root
 * shell). Linux however requires monotonically decreasing privileges.
 * This function will will perform some validation on Linux to make sure
 * that `execpromises` is a subset of `promises`. Your libc wrapper for
 * execve() will then apply its SECCOMP BPF filter later. Since Linux
 * has to do this before calling sys_execve(), the executed process will
 * be weakened to have execute permissions too.
 *
 * `__pledge_mode` is available to improve the experience of pledge() on
 * Linux. It should specify one of the following penalties:
 *
 * - `PLEDGE_PENALTY_KILL_THREAD` causes the violating thread to be
 *   killed. This is the default on Linux. It's effectively the same as
 *   killing the process, since redbean has no threads. The termination
 *   signal can't be caught and will be either `SIGSYS` or `SIGABRT`.
 *   Consider enabling stderr logging below so you'll know why your
 *   program failed. Otherwise check the system log.
 *
 * - `PLEDGE_PENALTY_KILL_PROCESS` causes the process and all its
 *   threads to be killed. This is always the case on OpenBSD.
 *
 * - `PLEDGE_PENALTY_RETURN_EPERM` causes system calls to just return an
 *   `EPERM` error instead of killing. This is a gentler solution that
 *   allows code to display a friendly warning. Please note this may
 *   lead to weird behaviors if the software being sandboxed is lazy
 *   about checking error results.
 *
 * `mode` may optionally bitwise or the following flags:
 *
 * - `PLEDGE_STDERR_LOGGING` enables friendly error message logging
 *   letting you know which promises are needed whenever violations
 *   occur. Without this, violations will be logged to `dmesg` on Linux
 *   if the penalty is to kill the process. You would then need to
 *   manually look up the system call number and then cross reference it
 *   with the cosmopolitan libc pledge() documentation. You can also use
 *   `strace -ff` which is easier. This is ignored OpenBSD, which
 *   already has a good system log. Turning on stderr logging (which
 *   uses SECCOMP trapping) also means that the `WTERMSIG()` on your
 *   killed processes will always be `SIGABRT` on both Linux and
 *   OpenBSD. Otherwise, Linux prefers to raise `SIGSYS`. Enabling this
 *   option might not be a good idea if you're pledging `exec` because
 *   subprocesses can't inherit the `SIGSYS` handler this installs.
 *
 * @return 0 on success, or -1 w/ errno
 * @raise EINVAL if `execpromises` on Linux isn't a subset of `promises`
 * @raise EINVAL if `promises` allows exec and `execpromises` is null
 * @threadsafe
 * @vforksafe
 */
int pledge(const char *promises, const char *execpromises) {
  int e, rc;
  unsigned long ipromises, iexecpromises;
  /*if (IsGenuineBlink()) {
    rc = 0;  // blink doesn't support seccomp
  } else*/ if (!ParsePromises(promises, &ipromises) &&
             !ParsePromises(execpromises, &iexecpromises)) {
    if (true /*IsLinux()*/) {
      // copy exec and execnative from promises to execpromises
      iexecpromises = ~(~iexecpromises | (~ipromises & (1ul << PROMISE_EXEC)));
      // if bits are missing in execpromises that exist in promises
      // then execpromises wouldn't be a monotonic access reduction
      // this check only matters when exec / execnative are allowed
      if ((ipromises & ~iexecpromises) &&
          (~ipromises & (1ul << PROMISE_EXEC))) {
        //STRACE("execpromises must be a subset of promises");
        errno = EINVAL;
        rc = -1;
      } else {
        rc = sys_pledge_linux(ipromises, __pledge_mode);
        if (rc > -4096u) errno = -rc, rc = -1;
      }
    } /*else {
      e = errno;
      rc = sys_pledge(promises, execpromises);
      if (rc && errno == ENOSYS) {
        errno = e;
        rc = 0;
      }
    }*/
    if (!rc && true/*!__vforked*/ &&
        (false/*IsOpenbsd()*/ || (true/*IsLinux()*/ && getpid() == gettid()))) {
      __promises = ipromises;
      __execpromises = iexecpromises;
    }
  } else {
    errno = EINVAL;
    rc = -1;
  }
  //STRACE("pledge(%#s, %#s) → %d% m", promises, execpromises, rc);
  return rc;
}


int main(int argc, char *argv[]) {
  const char *s;
  bool hasfunbits;
  int fdin, fdout;
  char buf[PATH_MAX];
  int e, zipfd, memfd;
  int useruid, usergid;
  int owneruid, ownergid;
  int oldfsuid, oldfsgid;
  unsigned long ipromises;

  // parse flags
  GetOpts(argc, argv);
  /*if (g_test) {
    if (!strcmp(g_test, "pledge")) {
      if (IsOpenbsd() || (IsLinux() && __is_linux_2_6_23())) {
        exit(0);
      } else {
        exit(1);
      }
    }
    if (!strcmp(g_test, "unveil")) {
      if (IsOpenbsd() || (IsLinux() && SupportsLandlock())) {
        exit(0);
      } else {
        exit(1);
      }
    }
    kprintf("error: unknown test: %s\n", g_test);
    exit(2);
  }*/
  if (optind == argc) {
    kprintf("error: too few args\n");
    write(2, USAGE, sizeof(USAGE) - 1);
    exit(64);
  }

  if (!g_noclose) {
    NormalizeFileDescriptors();
  }

  // set resource limits
  MakeProcessNice();

  if (SetCpuLimit(g_cpuquota) == -1) {
    kprintf("error: setrlimit(%s) failed: %m\n", "RLIMIT_CPU");
    exit(1);
  }

  if (SetLimit(RLIMIT_FSIZE, g_fszquota, g_fszquota * 1.5) == -1) {
    kprintf("error: setrlimit(%s) failed: %m\n", "RLIMIT_FSIZE");
    exit(1);
  }

  if (SetLimit(RLIMIT_AS, g_memquota, g_memquota) == -1) {
    kprintf("error: setrlimit(%s) failed: %m\n", "RLIMIT_AS");
    exit(1);
  }

  if (SetLimit(RLIMIT_NPROC, g_proquota, g_proquota) == -1) {
    kprintf("error: setrlimit(%s) failed: %m\n", "RLIMIT_NPROC");
    exit(1);
  }

  // test for weird chmod bits
  usergid = getgid();
  ownergid = getegid();
  useruid = getuid();
  owneruid = geteuid();
  hasfunbits = usergid != ownergid || useruid != owneruid;

  if (hasfunbits) {
    setuid(owneruid);
    setgid(ownergid);
  }

  // some flags can't be allowed if binary has setuid bits
  if (hasfunbits) {
    if (g_uflag || g_gflag) {
      kprintf("error: setuid flags forbidden on setuid binaries\n");
      _Exit(6);
    }
  }

  // check if user has permission to chroot directory
  if (hasfunbits && g_chroot) {
    oldfsuid = setfsuid(useruid);
    oldfsgid = setfsgid(usergid);
    if (access(g_chroot, R_OK) == -1) {
      kprintf("error: access(%#s) failed: %m\n", g_chroot);
      _Exit(7);
    }
    setfsuid(oldfsuid);
    setfsgid(oldfsgid);
  }

  // change root fs path
  if (g_chroot) {
    if (chdir(g_chroot) == -1) {
      kprintf("error: chdir(%#s) failed: %m\n", g_chroot);
      _Exit(8);
    }
    if (chroot(g_chroot) == -1) {
      kprintf("error: chroot(%#s) failed: %m\n", g_chroot);
      _Exit(9);
    }
  }

  // find program
  if (hasfunbits) {
    oldfsuid = setfsuid(useruid);
    oldfsgid = setfsgid(usergid);
  }
  if (!(prog = commandv(argv[optind], pathbuf, sizeof(pathbuf)))) {
    kprintf("error: command not found: %m\n", argv[optind]);
    _Exit(10);
  }
  if (hasfunbits) {
    setfsuid(oldfsuid);
    setfsgid(oldfsgid);
  }
  if (g_dontdrop) {
    if (hasfunbits) {
      kprintf("error: -D flag forbidden on setuid binaries\n");
      _Exit(6);
    }
  } else {
    DropCapabilities();
  }

  // set group id
  if (usergid != ownergid) {
    // setgid binaries must use the gid of the user that ran it
    if (setgid(usergid) == -1) {
      kprintf("error: setgid(%d) failed: %m\n", usergid);
      _Exit(11);
    }
    if (getgid() != usergid || getegid() != usergid) {
      kprintf("error: setgid() broken\n");
      _Exit(12);
    }
  } else if (g_gflag) {
    // otherwise we trust the gid flag
    if (setgid(g_gflag) == -1) {
      kprintf("error: setgid(%d) failed: %m\n", g_gflag);
      _Exit(13);
    }
    if (getgid() != g_gflag || getegid() != g_gflag) {
      kprintf("error: setgid() broken\n");
      _Exit(14);
    }
  }

  // set user id
  if (useruid != owneruid) {
    // setuid binaries must use the uid of the user that ran it
    if (setuid(useruid) == -1) {
      kprintf("error: setuid(%d) failed: %m\n", useruid);
      _Exit(15);
    }
    if (getuid() != useruid || geteuid() != useruid) {
      kprintf("error: setuid() broken\n");
      _Exit(16);
    }
  } else if (g_uflag) {
    // otherwise we trust the uid flag
    if (setuid(g_uflag) == -1) {
      kprintf("error: setuid(%d) failed: %m\n", g_uflag);
      _Exit(17);
    }
    if (getuid() != g_uflag || geteuid() != g_uflag) {
      kprintf("error: setuid() broken\n");
      _Exit(18);
    }
  }

  if (ParsePromises(g_promises, &ipromises) == -1) {
    kprintf("error: bad promises list: %s\n", g_promises);
    _Exit(21);
  }

  ApplyFilesystemPolicy(ipromises);

  // pledge.com uses the return eperm instead of killing the process
  // model. we do this becasue it's only possible to have sigsys print
  // crash messages if we're not pledging exec, which is what this tool
  // always has to do currently.
  if (g_kflag) {
    __pledge_mode = PLEDGE_PENALTY_KILL_PROCESS;
  } else {
    __pledge_mode = PLEDGE_PENALTY_RETURN_EPERM;
  }

  // we need to be able to call execv and mmap the dso
  // it'll be pledged away once/if the dso gets loaded
  if (!(~ipromises & (1ul << PROMISE_EXEC))) {
    g_promises = xstrcat(g_promises, ' ', "exec", NULL);
    if (!g_qflag) {
      __pledge_mode |= PLEDGE_STDERR_LOGGING;
    }
  }
  if (true) {
    g_promises = xstrcat(g_promises, ' ', "prot_exec", NULL);
  }

  // pass arguments to pledge() inside the dso
  if (false) {
    ksnprintf(buf, sizeof(buf), "_PLEDGE=%ld,%ld", ~ipromises, __pledge_mode);
    putenv(buf);
  }

  if (SetLimit(RLIMIT_NOFILE, g_nfdquota, g_nfdquota) == -1) {
    kprintf("error: setrlimit(%s) failed: %m\n", "RLIMIT_NOFILE");
    exit(1);
  }

  // apply sandbox
  if (pledge(g_promises, g_promises) == -1) {
    kprintf("error: pledge(%#s) failed: %m\n", g_promises);
    _Exit(19);
  }

  // launch program
  execve(prog, argv + optind, environ);
  kprintf("%s: execve failed: %m\n", prog);
  return 127;
}
