/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│ vi: set et ft=c ts=2 sts=2 sw=2 fenc=utf-8                               :vi │
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
#include "libc/macros.h"
#include "libc/nexgen32e/x86info.h"

const struct X86ProcessorModel kX86ProcessorModels[] = {
    /* <SORTED> */
    {0x060F, X86_MARCH_CORE2, X86_GRADE_CLIENT},
    {0x0616, X86_MARCH_CORE2, X86_GRADE_MOBILE},
    {0x0617, X86_MARCH_CORE2, X86_GRADE_SERVER},
    {0x061A, X86_MARCH_NEHALEM, X86_GRADE_DENSITY},
    {0x061C, X86_MARCH_BONNELL, X86_GRADE_APPLIANCE},
    {0x061D, X86_MARCH_CORE2, X86_GRADE_SERVER},
    {0x061E, X86_MARCH_NEHALEM, X86_GRADE_CLIENT},
    {0x061F, X86_MARCH_NEHALEM, X86_GRADE_DESKTOP},
    {0x0625, X86_MARCH_WESTMERE, X86_GRADE_CLIENT},
    {0x0626, X86_MARCH_BONNELL, X86_GRADE_TABLET},
    {0x0627, X86_MARCH_SALTWELL, X86_GRADE_TABLET},
    {0x062A, X86_MARCH_SANDYBRIDGE, X86_GRADE_CLIENT},
    {0x062C, X86_MARCH_WESTMERE, X86_GRADE_DENSITY},
    {0x062D, X86_MARCH_SANDYBRIDGE, X86_GRADE_SERVER},
    {0x062E, X86_MARCH_NEHALEM, X86_GRADE_SERVER},
    {0x062F, X86_MARCH_WESTMERE, X86_GRADE_SERVER},
    {0x0635, X86_MARCH_SALTWELL, X86_GRADE_TABLET},
    {0x0636, X86_MARCH_SALTWELL, X86_GRADE_APPLIANCE},
    {0x0637, X86_MARCH_SILVERMONT, X86_GRADE_APPLIANCE},
    {0x063A, X86_MARCH_IVYBRIDGE, X86_GRADE_CLIENT},
    {0x063C, X86_MARCH_HASWELL, X86_GRADE_CLIENT},
    {0x063D, X86_MARCH_BROADWELL, X86_GRADE_CLIENT},
    {0x063E, X86_MARCH_IVYBRIDGE, X86_GRADE_SERVER},
    {0x063F, X86_MARCH_HASWELL, X86_GRADE_SERVER},
    {0x0645, X86_MARCH_HASWELL, X86_GRADE_MOBILE},
    {0x0646, X86_MARCH_HASWELL, X86_GRADE_DESKTOP},
    {0x0647, X86_MARCH_BROADWELL, X86_GRADE_DESKTOP},
    {0x064A, X86_MARCH_SILVERMONT, X86_GRADE_TABLET},
    {0x064C, X86_MARCH_AIRMONT, X86_GRADE_APPLIANCE},
    {0x064D, X86_MARCH_SILVERMONT, X86_GRADE_DENSITY},
    {0x064E, X86_MARCH_SKYLAKE, X86_GRADE_MOBILE},
    {0x064F, X86_MARCH_BROADWELL, X86_GRADE_SERVER},
    {0x0655, X86_MARCH_SKYLAKE, X86_GRADE_SERVER},
    {0x0656, X86_MARCH_BROADWELL, X86_GRADE_DENSITY},
    {0x0657, X86_MARCH_KNIGHTSLANDING, X86_GRADE_SCIENCE},
    {0x065A, X86_MARCH_AIRMONT, X86_GRADE_TABLET},
    {0x065C, X86_MARCH_GOLDMONT, X86_GRADE_APPLIANCE},
    {0x065E, X86_MARCH_SKYLAKE, X86_GRADE_CLIENT},
    {0x065F, X86_MARCH_GOLDMONT, X86_GRADE_DENSITY},
    {0x0666, X86_MARCH_CANNONLAKE, X86_GRADE_MOBILE},
    {0x066A, X86_MARCH_ICELAKE, X86_GRADE_SERVER},
    {0x066C, X86_MARCH_ICELAKE, X86_GRADE_DENSITY},
    {0x0675, X86_MARCH_AIRMONT, X86_GRADE_APPLIANCE},
    {0x067A, X86_MARCH_GOLDMONTPLUS, X86_GRADE_APPLIANCE},
    {0x067D, X86_MARCH_ICELAKE, X86_GRADE_CLIENT},
    {0x067E, X86_MARCH_ICELAKE, X86_GRADE_MOBILE},
    {0x0685, X86_MARCH_KNIGHTSMILL, X86_GRADE_SCIENCE},
    {0x0686, X86_MARCH_TREMONT, X86_GRADE_APPLIANCE},
    {0x068A, X86_MARCH_TREMONT, X86_GRADE_APPLIANCE},
    {0x068C, X86_MARCH_TIGERLAKE, X86_GRADE_MOBILE},
    {0x068D, X86_MARCH_TIGERLAKE, X86_GRADE_CLIENT},
    {0x068E, X86_MARCH_KABYLAKE, X86_GRADE_MOBILE},
    {0x068F, X86_MARCH_SAPPHIRERAPIDS, X86_GRADE_SERVER},
    {0x0696, X86_MARCH_TREMONT, X86_GRADE_APPLIANCE},
    {0x0696, X86_MARCH_TREMONT, X86_GRADE_APPLIANCE},
    {0x0697, X86_MARCH_ALDERLAKE, X86_GRADE_CLIENT},
    {0x069A, X86_MARCH_ALDERLAKE, X86_GRADE_CLIENT},
    {0x069C, X86_MARCH_TREMONT, X86_GRADE_APPLIANCE},
    {0x069D, X86_MARCH_ICELAKE, X86_GRADE_SCIENCE},
    {0x069E, X86_MARCH_KABYLAKE, X86_GRADE_CLIENT},
    {0x06A5, X86_MARCH_COMETLAKE, X86_GRADE_CLIENT},
    {0x06A7, X86_MARCH_ROCKETLAKE, X86_GRADE_CLIENT},
    {0x06B7, X86_MARCH_RAPTORLAKE, X86_GRADE_CLIENT},
    {0x06BA, X86_MARCH_RAPTORLAKE, X86_GRADE_CLIENT},
    /* </SORTED> */
};

const size_t kX86ProcessorModelCount = ARRAYLEN(kX86ProcessorModels);
