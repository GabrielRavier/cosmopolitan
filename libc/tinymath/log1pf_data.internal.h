#ifndef COSMOPOLITAN_LIBC_TINYMATH_LOG1PF_DATA_H_
#define COSMOPOLITAN_LIBC_TINYMATH_LOG1PF_DATA_H_
#if !(__ASSEMBLER__ + __LINKER__ + 0)
COSMOPOLITAN_C_START_

#define LOG1PF_2U5
#define V_LOG1PF_2U5
#define LOG1PF_NCOEFFS 9
extern const struct log1pf_data {
  float coeffs[LOG1PF_NCOEFFS];  //
} __log1pf_data;

COSMOPOLITAN_C_END_
#endif /* !(__ASSEMBLER__ + __LINKER__ + 0) */
#endif /* COSMOPOLITAN_LIBC_TINYMATH_LOG1PF_DATA_H_ */
