#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4336-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151919);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2016-2226",
    "CVE-2016-4487",
    "CVE-2016-4488",
    "CVE-2016-4489",
    "CVE-2016-4490",
    "CVE-2016-4491",
    "CVE-2016-4492",
    "CVE-2016-4493",
    "CVE-2016-6131",
    "CVE-2017-6965",
    "CVE-2017-6966",
    "CVE-2017-6969",
    "CVE-2017-7209",
    "CVE-2017-7210",
    "CVE-2017-7223",
    "CVE-2017-7224",
    "CVE-2017-7225",
    "CVE-2017-7226",
    "CVE-2017-7227",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7302",
    "CVE-2017-7614",
    "CVE-2017-8393",
    "CVE-2017-8394",
    "CVE-2017-8395",
    "CVE-2017-8396",
    "CVE-2017-8397",
    "CVE-2017-8398",
    "CVE-2017-8421",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9040",
    "CVE-2017-9041",
    "CVE-2017-9042",
    "CVE-2017-9044",
    "CVE-2017-9742",
    "CVE-2017-9744",
    "CVE-2017-9745",
    "CVE-2017-9746",
    "CVE-2017-9747",
    "CVE-2017-9748",
    "CVE-2017-9749",
    "CVE-2017-9750",
    "CVE-2017-9751",
    "CVE-2017-9752",
    "CVE-2017-9753",
    "CVE-2017-9754",
    "CVE-2017-9755",
    "CVE-2017-9756",
    "CVE-2017-9954",
    "CVE-2017-12448",
    "CVE-2017-12449",
    "CVE-2017-12450",
    "CVE-2017-12451",
    "CVE-2017-12452",
    "CVE-2017-12453",
    "CVE-2017-12454",
    "CVE-2017-12455",
    "CVE-2017-12456",
    "CVE-2017-12457",
    "CVE-2017-12458",
    "CVE-2017-12459",
    "CVE-2017-12799",
    "CVE-2017-12967",
    "CVE-2017-13710",
    "CVE-2017-14128",
    "CVE-2017-14129",
    "CVE-2017-14130",
    "CVE-2017-14333",
    "CVE-2017-14529",
    "CVE-2017-14930",
    "CVE-2017-14932",
    "CVE-2017-14938",
    "CVE-2017-14939",
    "CVE-2017-14940",
    "CVE-2017-15020",
    "CVE-2017-15021",
    "CVE-2017-15022",
    "CVE-2017-15024",
    "CVE-2017-15025",
    "CVE-2017-15225",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-15996",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16831",
    "CVE-2017-16832",
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2018-6323",
    "CVE-2018-6543",
    "CVE-2018-6759",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-9138",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12698",
    "CVE-2018-12699",
    "CVE-2018-12934",
    "CVE-2018-13033",
    "CVE-2018-17358",
    "CVE-2018-17359",
    "CVE-2018-17360",
    "CVE-2018-17794",
    "CVE-2018-17985",
    "CVE-2018-18309",
    "CVE-2018-18483",
    "CVE-2018-18484",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-18700",
    "CVE-2018-18701",
    "CVE-2018-19931",
    "CVE-2018-19932",
    "CVE-2018-20002",
    "CVE-2018-20623",
    "CVE-2018-20671",
    "CVE-2018-1000876",
    "CVE-2019-9070",
    "CVE-2019-9071",
    "CVE-2019-9073",
    "CVE-2019-9074",
    "CVE-2019-9075",
    "CVE-2019-9077",
    "CVE-2019-12972",
    "CVE-2019-14250",
    "CVE-2019-14444",
    "CVE-2019-17450",
    "CVE-2019-17451"
  );
  script_xref(name:"USN", value:"4336-2");

  script_name(english:"Ubuntu 16.04 LTS : GNU binutils vulnerabilities (USN-4336-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4336-2 advisory.

  - Integer overflow in the string_appends function in cplus-dem.c in libiberty allows remote attackers to
    execute arbitrary code via a crafted executable, which triggers a buffer overflow. (CVE-2016-2226)

  - Use-after-free vulnerability in libiberty allows remote attackers to cause a denial of service
    (segmentation fault and crash) via a crafted binary, related to btypevec. (CVE-2016-4487)

  - Use-after-free vulnerability in libiberty allows remote attackers to cause a denial of service
    (segmentation fault and crash) via a crafted binary, related to ktypevec. (CVE-2016-4488)

  - Integer overflow in the gnu_special function in libiberty allows remote attackers to cause a denial of
    service (segmentation fault and crash) via a crafted binary, related to the demangling of virtual
    tables. (CVE-2016-4489)

  - Integer overflow in cp-demangle.c in libiberty allows remote attackers to cause a denial of service
    (segmentation fault and crash) via a crafted binary, related to inconsistent use of the long and int types
    for lengths. (CVE-2016-4490)

  - The d_print_comp function in cp-demangle.c in libiberty allows remote attackers to cause a denial of
    service (segmentation fault and crash) via a crafted binary, which triggers infinite recursion and a
    buffer overflow, related to a node having itself as ancestor more than once. (CVE-2016-4491)

  - Buffer overflow in the do_type function in cplus-dem.c in libiberty allows remote attackers to cause a
    denial of service (segmentation fault and crash) via a crafted binary. (CVE-2016-4492)

  - The demangle_template_value_parm and do_hpacc_template_literal functions in cplus-dem.c in libiberty allow
    remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted binary.
    (CVE-2016-4493)

  - The demangler in GNU Libiberty allows remote attackers to cause a denial of service (infinite loop, stack
    overflow, and crash) via a cycle in the references of remembered mangled types. (CVE-2016-6131)

  - readelf in GNU Binutils 2.28 writes to illegal addresses while processing corrupt input files containing
    symbol-difference relocations, leading to a heap-based buffer overflow. (CVE-2017-6965)

  - readelf in GNU Binutils 2.28 has a use-after-free (specifically read-after-free) error while processing
    multiple, relocated sections in an MSP430 binary. This is caused by mishandling of an invalid symbol
    index, and mishandling of state across invocations. (CVE-2017-6966)

  - readelf in GNU Binutils 2.28 is vulnerable to a heap-based buffer over-read while processing corrupt RL78
    binaries. The vulnerability can trigger program crashes. It may lead to an information leak as well.
    (CVE-2017-6969)

  - The dump_section_as_bytes function in readelf in GNU Binutils 2.28 accesses a NULL pointer while reading
    section contents in a corrupt binary, leading to a program crash. (CVE-2017-7209)

  - objdump in GNU Binutils 2.28 is vulnerable to multiple heap-based buffer over-reads (of size 1 and size 8)
    while handling corrupt STABS enum type strings in a crafted object file, leading to program crash.
    (CVE-2017-7210)

  - GNU assembler in GNU Binutils 2.28 is vulnerable to a global buffer overflow (of size 1) while attempting
    to unget an EOF character from the input stream, potentially leading to a program crash. (CVE-2017-7223)

  - The find_nearest_line function in objdump in GNU Binutils 2.28 is vulnerable to an invalid write (of size
    1) while disassembling a corrupt binary that contains an empty function name, leading to a program crash.
    (CVE-2017-7224)

  - The find_nearest_line function in addr2line in GNU Binutils 2.28 does not handle the case where the main
    file name and the directory name are both empty, triggering a NULL pointer dereference and an invalid
    write, and leading to a program crash. (CVE-2017-7225)

  - The pe_ILF_object_p function in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.28, is vulnerable to a heap-based buffer over-read of size 4049 because it uses the strlen
    function instead of strnlen, leading to program crashes in several utilities such as addr2line, size, and
    strings. It could lead to information disclosure as well. (CVE-2017-7226)

  - GNU linker (ld) in GNU Binutils 2.28 is vulnerable to a heap-based buffer overflow while processing a
    bogus input script, leading to a program crash. This relates to lack of '\0' termination of a name field
    in ldlex.l. (CVE-2017-7227)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has an invalid
    read (of size 8) because the code to emit relocs (bfd_elf_final_link function in bfd/elflink.c) does not
    check the format of the input file before trying to read the ELF reloc section header. The vulnerability
    leads to a GNU linker (ld) program crash. (CVE-2017-7299)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has an
    aout_link_add_symbols function in bfd/aoutx.h that is vulnerable to a heap-based buffer over-read (off-by-
    one) because of an incomplete check for invalid string offsets while loading symbols, leading to a GNU
    linker (ld) program crash. (CVE-2017-7300)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has an
    aout_link_add_symbols function in bfd/aoutx.h that has an off-by-one vulnerability because it does not
    carefully check the string offset. The vulnerability could lead to a GNU linker (ld) program crash.
    (CVE-2017-7301)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has a
    swap_std_reloc_out function in bfd/aoutx.h that is vulnerable to an invalid read (of size 4) because of
    missing checks for relocs that could not be recognised. This vulnerability causes Binutils utilities like
    strip to crash. (CVE-2017-7302)

  - elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28,
    has a member access within null pointer undefined behavior issue, which might allow remote attackers to
    cause a denial of service (application crash) or possibly have unspecified other impact via an int main()
    {return 0;} program. (CVE-2017-7614)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable
    to a global buffer over-read error because of an assumption made by code that runs for objcopy and strip,
    that SHT_REL/SHR_RELA sections are always named starting with a .rel/.rela prefix. This vulnerability
    causes programs that conduct an analysis of binary programs using the libbfd library, such as objcopy and
    strip, to crash. (CVE-2017-8393)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable
    to an invalid read of size 4 due to NULL pointer dereferencing of _bfd_elf_large_com_section. This
    vulnerability causes programs that conduct an analysis of binary programs using the libbfd library, such
    as objcopy, to crash. (CVE-2017-8394)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable
    to an invalid write of size 8 because of missing a malloc() return-value check to see if memory had
    actually been allocated in the _bfd_generic_get_section_contents function. This vulnerability causes
    programs that conduct an analysis of binary programs using the libbfd library, such as objcopy, to crash.
    (CVE-2017-8395)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable
    to an invalid read of size 1 because the existing reloc offset range tests didn't catch small negative
    offsets less than the size of the reloc field. This vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as objdump, to crash. (CVE-2017-8396)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable
    to an invalid read of size 1 and an invalid write of size 1 during processing of a corrupt binary
    containing reloc(s) with negative addresses. This vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as objdump, to crash. (CVE-2017-8397)

  - dwarf.c in GNU Binutils 2.28 is vulnerable to an invalid read of size 1 during dumping of debug
    information from a corrupt binary. This vulnerability causes programs that conduct an analysis of binary
    programs, such as objdump and readelf, to crash. (CVE-2017-8398)

  - The function coff_set_alignment_hook in coffcode.h in Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has a memory leak vulnerability which can cause memory exhaustion in
    objdump via a crafted PE file. Additional validation in dump_relocs_in_section in objdump.c can resolve
    this. (CVE-2017-8421)

  - GNU Binutils 2.28 allows remote attackers to cause a denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to the byte_get_little_endian function in elfcomm.c,
    the get_unwind_section_word function in readelf.c, and ARM unwind information that contains invalid word
    offsets. (CVE-2017-9038)

  - GNU Binutils 2.28 allows remote attackers to cause a denial of service (memory consumption) via a crafted
    ELF file with many program headers, related to the get_program_headers function in readelf.c.
    (CVE-2017-9039)

  - GNU Binutils 2017-04-03 allows remote attackers to cause a denial of service (NULL pointer dereference and
    application crash), related to the process_mips_specific function in readelf.c, via a crafted ELF file
    that triggers a large memory-allocation attempt. (CVE-2017-9040)

  - GNU Binutils 2.28 allows remote attackers to cause a denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to MIPS GOT mishandling in the process_mips_specific
    function in readelf.c. (CVE-2017-9041)

  - readelf.c in GNU Binutils 2017-04-12 has a cannot be represented in type long issue, which might allow
    remote attackers to cause a denial of service (application crash) or possibly have unspecified other
    impact via a crafted ELF file. (CVE-2017-9042)

  - The print_symbol_for_build_attribute function in readelf.c in GNU Binutils 2017-04-12 allows remote
    attackers to cause a denial of service (invalid read and SEGV) via a crafted ELF file. (CVE-2017-9044)

  - The score_opcodes function in opcodes/score7-dis.c in GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (buffer overflow and application crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of this file during objdump -D execution.
    (CVE-2017-9742)

  - The sh_elf_set_mach_from_flags function in bfd/elf32-sh.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.28, allows remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during objdump -D execution. (CVE-2017-9744)

  - The _bfd_vms_slurp_etir function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.28, allows remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during objdump -D execution. (CVE-2017-9745)

  - The disassemble_bytes function in objdump.c in GNU Binutils 2.28 allows remote attackers to cause a denial
    of service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of rae insns printing for this file during objdump -D
    execution. (CVE-2017-9746)

  - The ieee_archive_p function in bfd/ieee.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during objdump -D execution. NOTE: this may be related to a
    compiler bug. (CVE-2017-9747)

  - The ieee_object_p function in bfd/ieee.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during objdump -D execution. NOTE: this may be related to a
    compiler bug. (CVE-2017-9748)

  - The *regs* macros in opcodes/bfin-dis.c in GNU Binutils 2.28 allow remote attackers to cause a denial of
    service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this file during objdump -D execution. (CVE-2017-9749)

  - opcodes/rx-decode.opc in GNU Binutils 2.28 lacks bounds checks for certain scale arrays, which allows
    remote attackers to cause a denial of service (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as demonstrated by mishandling of this file during
    objdump -D execution. (CVE-2017-9750)

  - opcodes/rl78-decode.opc in GNU Binutils 2.28 has an unbounded GETBYTE macro, which allows remote attackers
    to cause a denial of service (buffer overflow and application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by mishandling of this file during objdump -D
    execution. (CVE-2017-9751)

  - bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils
    2.28, allows remote attackers to cause a denial of service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted binary file, as demonstrated by mishandling of this
    file in the _bfd_vms_get_value and _bfd_vms_slurp_etir functions during objdump -D execution.
    (CVE-2017-9752)

  - The versados_mkobject function in bfd/versados.c in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, does not initialize a certain data structure, which allows remote
    attackers to cause a denial of service (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as demonstrated by mishandling of this file during
    objdump -D execution. (CVE-2017-9753)

  - The process_otr function in bfd/versados.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, does not validate a certain offset, which allows remote attackers to
    cause a denial of service (buffer overflow and application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by mishandling of this file during objdump -D
    execution. (CVE-2017-9754)

  - opcodes/i386-dis.c in GNU Binutils 2.28 does not consider the number of registers for bnd mode, which
    allows remote attackers to cause a denial of service (buffer overflow and application crash) or possibly
    have unspecified other impact via a crafted binary file, as demonstrated by mishandling of this file
    during objdump -D execution. (CVE-2017-9755)

  - The aarch64_ext_ldst_reglist function in opcodes/aarch64-dis.c in GNU Binutils 2.28 allows remote
    attackers to cause a denial of service (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as demonstrated by mishandling of this file during
    objdump -D execution. (CVE-2017-9756)

  - The getvalue function in tekhex.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.28, allows remote attackers to cause a denial of service (stack-based buffer over-read
    and application crash) via a crafted tekhex file, as demonstrated by mishandling within the nm program.
    (CVE-2017-9954)

  - The bfd_cache_close function in bfd/cache.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause a heap use after free and
    possibly achieve code execution via a crafted nested archive file. This issue occurs because incorrect
    functions are called during an attempt to release memory. The issue can be addressed by better input
    validation in the bfd_generic_archive_p function in bfd/archive.c. (CVE-2017-12448)

  - The _bfd_vms_save_sized_string function in vms-misc.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of
    bounds heap read via a crafted vms file. (CVE-2017-12449)

  - The alpha_vms_object_p function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of
    bounds heap write and possibly achieve code execution via a crafted vms alpha file. (CVE-2017-12450)

  - The _bfd_xcoff_read_ar_hdr function in bfd/coff-rs6000.c and bfd/coff64-rs6000.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote
    attackers to cause an out of bounds stack read via a crafted COFF image file. (CVE-2017-12451)

  - The bfd_mach_o_i386_canonicalize_one_reloc function in bfd/mach-o-i386.c in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to
    cause an out of bounds heap read via a crafted mach-o file. (CVE-2017-12452)

  - The _bfd_vms_slurp_eeom function in libbfd.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap read
    via a crafted vms alpha file. (CVE-2017-12453)

  - The _bfd_vms_slurp_egsd function in bfd/vms-alpha.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an arbitrary
    memory read via a crafted vms alpha file. (CVE-2017-12454)

  - The evax_bfd_print_emh function in vms-alpha.c in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of bounds heap
    read via a crafted vms alpha file. (CVE-2017-12455)

  - The read_symbol_stabs_debugging_info function in rddbg.c in GNU Binutils 2.29 and earlier allows remote
    attackers to cause an out of bounds heap read via a crafted binary file. (CVE-2017-12456)

  - The bfd_make_section_with_flags function in section.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause a NULL
    dereference via a crafted file. (CVE-2017-12457)

  - The nlm_swap_auxiliary_headers_in function in bfd/nlmcode.h in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of
    bounds heap read via a crafted nlm file. (CVE-2017-12458)

  - The bfd_mach_o_read_symtab_strtab function in bfd/mach-o.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29 and earlier, allows remote attackers to cause an out of
    bounds heap write and possibly achieve code execution via a crafted mach-o file. (CVE-2017-12459)

  - The elf_read_notesfunction in bfd/elf.c in GNU Binutils 2.29 allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or possibly have unspecified other impact via a crafted
    binary file. (CVE-2017-12799)

  - The getsym function in tekhex.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause a denial of service (stack-based buffer over-read
    and application crash) via a malformed tekhex binary. (CVE-2017-12967)

  - The setup_group function in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause a denial of service (NULL pointer dereference and
    application crash) via a group section that is too small. (CVE-2017-13710)

  - The decode_line_info function in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (read_1_byte heap-
    based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-14128)

  - The read_section function in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (parse_comp_unit
    heap-based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-14129)

  - The _bfd_elf_parse_attributes function in elf-attrs.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service
    (_bfd_elf_attr_strdup heap-based buffer over-read and application crash) via a crafted ELF file.
    (CVE-2017-14130)

  - The process_version_sections function in readelf.c in GNU Binutils 2.29 allows attackers to cause a denial
    of service (Integer Overflow, and hang because of a time-consuming loop) or possibly have unspecified
    other impact via a crafted binary file with invalid values of ent.vn_next, during readelf -a execution.
    (CVE-2017-14333)

  - The pe_print_idata function in peXXigen.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, mishandles HintName vector entries, which allows remote attackers to
    cause a denial of service (heap-based buffer over-read and application crash) via a crafted PE file,
    related to the bfd_getl16 function. (CVE-2017-14529)

  - Memory leak in decode_line_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (memory
    consumption) via a crafted ELF file. (CVE-2017-14930)

  - decode_line_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.29, allows remote attackers to cause a denial of service (infinite loop) via a crafted ELF
    file. (CVE-2017-14932)

  - _bfd_elf_slurp_version_tables in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (excessive memory
    allocation and application crash) via a crafted ELF file. (CVE-2017-14938)

  - decode_line_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.29, mishandles a length calculation, which allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application crash) via a crafted ELF file, related to
    read_1_byte. (CVE-2017-14939)

  - scan_unit_for_symbols in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause a denial of service (NULL pointer dereference and
    application crash) via a crafted ELF file. (CVE-2017-14940)

  - dwarf1.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29,
    mishandles pointers, which allows remote attackers to cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted ELF file, related to parse_die and parse_line_table,
    as demonstrated by a parse_die heap-based buffer over-read. (CVE-2017-15020)

  - bfd_get_debug_link_info_1 in opncls.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (heap-based buffer
    over-read and application crash) via a crafted ELF file, related to bfd_getl32. (CVE-2017-15021)

  - dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29,
    does not validate the DW_AT_name data type, which allows remote attackers to cause a denial of service
    (bfd_hash_hash NULL pointer dereference, or out-of-bounds access, and application crash) via a crafted ELF
    file, related to scan_unit_for_symbols and parse_comp_unit. (CVE-2017-15022)

  - find_abstract_instance_name in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (infinite recursion
    and application crash) via a crafted ELF file. (CVE-2017-15024)

  - decode_line_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.29, allows remote attackers to cause a denial of service (divide-by-zero error and
    application crash) via a crafted ELF file. (CVE-2017-15025)

  - _bfd_dwarf2_cleanup_debug_info in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (memory leak) via a
    crafted ELF file. (CVE-2017-15225)

  - dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29,
    miscalculates DW_FORM_ref_addr die refs in the case of a relocatable object file, which allows remote
    attackers to cause a denial of service (find_abstract_instance_name invalid memory read, segmentation
    fault, and application crash). (CVE-2017-15938)

  - dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29,
    mishandles NULL files in a .debug_line file table, which allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash) via a crafted ELF file, related to
    concat_filename. NOTE: this issue is caused by an incomplete fix for CVE-2017-15023. (CVE-2017-15939)

  - elfcomm.c in readelf in GNU Binutils 2.29 allows remote attackers to cause a denial of service (excessive
    memory allocation) or possibly have unspecified other impact via a crafted ELF file that triggers a
    buffer overflow on fuzzed archive header, related to an uninitialized variable, an improper conditional
    jump, and the get_archive_member_name, process_archive_index_and_symbols, and setup_archive functions.
    (CVE-2017-15996)

  - The coff_slurp_line_table function in coffcode.h in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote attackers to cause a denial of service (invalid
    memory access and application crash) or possibly have unspecified other impact via a crafted PE file.
    (CVE-2017-16826)

  - The aout_get_external_symbols function in aoutx.h in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, allows remote attackers to cause a denial of service
    (slurp_symtab invalid free and application crash) or possibly have unspecified other impact via a crafted
    ELF file. (CVE-2017-16827)

  - The display_debug_frames function in dwarf.c in GNU Binutils 2.29.1 allows remote attackers to cause a
    denial of service (integer overflow and heap-based buffer over-read, and application crash) or possibly
    have unspecified other impact via a crafted ELF file, related to print_debug_frame. (CVE-2017-16828)

  - coffgen.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1,
    does not validate the symbol count, which allows remote attackers to cause a denial of service (integer
    overflow and application crash, or excessive memory allocation) or possibly have unspecified other impact
    via a crafted PE file. (CVE-2017-16831)

  - The pe_bfd_read_buildid function in peicode.h in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, does not validate size and offset values in the data dictionary, which
    allows remote attackers to cause a denial of service (segmentation violation and application crash) or
    possibly have unspecified other impact via a crafted PE file. (CVE-2017-16832)

  - elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1,
    does not validate sizes of core notes, which allows remote attackers to cause a denial of service
    (bfd_getl32 heap-based buffer over-read and application crash) via a crafted object file, related to
    elfcore_grok_netbsd_procinfo, elfcore_grok_openbsd_procinfo, and elfcore_grok_nto_status. (CVE-2017-17080)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.29.1, allows
    remote attackers to cause a denial of service (memory access violation) or possibly have unspecified other
    impact via a COFF binary in which a relocation refers to a location after the end of the to-be-relocated
    section. (CVE-2017-17121)

  - The coff_slurp_reloc_table function in coffcode.h in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, allows remote attackers to cause a denial of service (NULL
    pointer dereference and application crash) via a crafted COFF based file. (CVE-2017-17123)

  - The _bfd_coff_read_string_table function in coffgen.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, does not properly validate the size of the external string
    table, which allows remote attackers to cause a denial of service (excessive memory consumption, or heap-
    based buffer overflow and application crash) or possibly have unspecified other impact via a crafted COFF
    binary. (CVE-2017-17124)

  - nm.c and objdump.c in GNU Binutils 2.29.1 mishandle certain global symbols, which allows remote attackers
    to cause a denial of service (_bfd_elf_get_symbol_version_string buffer over-read and application crash)
    or possibly have unspecified other impact via a crafted ELF file. (CVE-2017-17125)

  - The elf_object_p function in elfcode.h in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, has an unsigned integer overflow because bfd_size_type multiplication
    is not used. A crafted ELF file allows remote attackers to cause a denial of service (application crash)
    or possibly have unspecified other impact. (CVE-2018-6323)

  - In GNU Binutils 2.30, there's an integer overflow in the function load_specific_debug_section() in
    objdump.c, which results in `malloc()` with 0 size. A crafted ELF file allows remote attackers to cause a
    denial of service (application crash) or possibly have unspecified other impact. (CVE-2018-6543)

  - The bfd_get_debug_link_info_1 function in opncls.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.30, has an unchecked strnlen operation. Remote attackers could
    leverage this vulnerability to cause a denial of service (segmentation fault) via a crafted ELF file.
    (CVE-2018-6759)

  - In the coff_pointerize_aux function in coffgen.c in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.30, an index is not validated, which allows remote attackers to cause a
    denial of service (segmentation fault) or possibly have unspecified other impact via a crafted file, as
    demonstrated by objcopy of a COFF object. (CVE-2018-7208)

  - The parse_die function in dwarf1.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote attackers to cause a denial of service (integer overflow
    and application crash) via an ELF file with corrupt dwarf1 debug information, as demonstrated by nm.
    (CVE-2018-7568)

  - dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.30,
    allows remote attackers to cause a denial of service (integer underflow or overflow, and application
    crash) via an ELF file with a corrupt DWARF FORM block, as demonstrated by nm. (CVE-2018-7569)

  - The swap_std_reloc_in function in aoutx.h in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference and application crash) via a crafted ELF file, as
    demonstrated by objcopy. (CVE-2018-7642)

  - The display_debug_ranges function in dwarf.c in GNU Binutils 2.30 allows remote attackers to cause a
    denial of service (integer overflow and application crash) or possibly have unspecified other impact via a
    crafted ELF file, as demonstrated by objdump. (CVE-2018-7643)

  - The bfd_section_from_shdr function in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote attackers to cause a denial of service (segmentation
    fault) via a large attribute section. (CVE-2018-8945)

  - An issue was discovered in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.29 and 2.30.
    Stack Exhaustion occurs in the C++ demangling functions provided by libiberty, and there are recursive
    stack frames: demangle_nested_args, demangle_args, do_arg, and do_type. (CVE-2018-9138)

  - process_cu_tu_index in dwarf.c in GNU Binutils 2.30 allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via a crafted binary file, as demonstrated by readelf.
    (CVE-2018-10372)

  - concat_filename in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.30, allows remote attackers to cause a denial of service (NULL pointer dereference and
    application crash) via a crafted binary file, as demonstrated by nm-new. (CVE-2018-10373)

  - The _bfd_XX_bfd_copy_private_bfd_data_common function in peXXigen.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils 2.30, processes a negative Data Directory size with
    an unbounded loop that increases the value of (external_IMAGE_DEBUG_DIRECTORY) *edd so that the address
    exceeds its own memory region, resulting in an out-of-bounds memory write, as demonstrated by objcopy
    copying private info with _bfd_pex64_bfd_copy_private_bfd_data_common in pex64igen.c. (CVE-2018-10534)

  - The ignore_section_sym function in elf.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, does not validate the output_section pointer in the case of a symtab
    entry with a SECTION type that has a 0 value, which allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash) via a crafted file, as demonstrated by objcopy.
    (CVE-2018-10535)

  - An issue was discovered in arm_pt in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30.
    Stack Exhaustion occurs in the C++ demangling functions provided by libiberty, and there are recursive
    stack frames: demangle_arm_hp_template, demangle_class_name, demangle_fund_type, do_type, do_arg,
    demangle_args, and demangle_nested_args. This can occur during execution of nm-new. (CVE-2018-12641)

  - A NULL pointer dereference (aka SEGV on unknown address 0x000000000000) was discovered in
    work_stuff_copy_to_from in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30. This can
    occur during execution of objdump. (CVE-2018-12697)

  - demangle_template in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30, allows attackers
    to trigger excessive memory consumption (aka OOM) during the Create an array for saving the template
    argument values XNEWVEC call. This can occur during execution of objdump. (CVE-2018-12698)

  - finish_stab in stabs.c in GNU Binutils 2.30 allows attackers to cause a denial of service (heap-based
    buffer overflow) or possibly have unspecified other impact, as demonstrated by an out-of-bounds write of 8
    bytes. This can occur during execution of objdump. (CVE-2018-12699)

  - A Stack Exhaustion issue was discovered in debug_write_type in debug.c in GNU Binutils 2.30 because of
    DEBUG_KIND_INDIRECT infinite recursion. (CVE-2018-12700)

  - remember_Ktype in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30, allows attackers to
    trigger excessive memory consumption (aka OOM). This can occur during execution of cxxfilt.
    (CVE-2018-12934)

  - The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (excessive memory allocation and application crash) via a crafted
    ELF file, as demonstrated by _bfd_elf_parse_attributes in elf-attrs.c and bfd_malloc in libbfd.c. This can
    occur during execution of nm. (CVE-2018-13033)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory access exists in _bfd_stab_section_find_nearest_line in syms.c. Attackers
    could leverage this vulnerability to cause a denial of service (application crash) via a crafted ELF file.
    (CVE-2018-17358)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory access exists in bfd_zalloc in opncls.c. Attackers could leverage this
    vulnerability to cause a denial of service (application crash) via a crafted ELF file. (CVE-2018-17359)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. a heap-based buffer over-read in bfd_getl32 in libbfd.c allows an attacker to cause a
    denial of service through a crafted PE file. This vulnerability can be triggered by the executable
    objdump. (CVE-2018-17360)

  - An issue was discovered in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31. There is a
    NULL pointer dereference in work_stuff_copy_to_from when called from iterate_demangle_function.
    (CVE-2018-17794)

  - An issue was discovered in cp-demangle.c in GNU libiberty, as distributed in GNU Binutils 2.31. There is a
    stack consumption problem caused by the cplus_demangle_type function making recursive calls to itself in
    certain scenarios involving many 'P' characters. (CVE-2018-17985)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory address dereference was discovered in read_reloc in reloc.c. The
    vulnerability causes a segmentation fault and application crash, which leads to denial of service, as
    demonstrated by objdump, because of missing _bfd_clear_contents bounds checking. (CVE-2018-18309)

  - The get_count function in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31, allows remote
    attackers to cause a denial of service (malloc called with the result of an integer-overflowing
    calculation) or possibly have unspecified other impact via a crafted string, as demonstrated by c++filt.
    (CVE-2018-18483)

  - An issue was discovered in cp-demangle.c in GNU libiberty, as distributed in GNU Binutils 2.31. Stack
    Exhaustion occurs in the C++ demangling functions provided by libiberty, and there is a stack consumption
    problem caused by recursive stack frames: cplus_demangle_type, d_bare_function_type, d_function_type.
    (CVE-2018-18484)

  - A heap-based buffer over-read issue was discovered in the function sec_merge_hash_lookup in merge.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.31, because
    _bfd_add_merge_section mishandles section merges when size is not a multiple of entsize. A specially
    crafted ELF allows remote attackers to cause a denial of service, as demonstrated by ld. (CVE-2018-18605)

  - An issue was discovered in the merge_strings function in merge.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in
    _bfd_add_merge_section when attempting to merge sections with large alignments. A specially crafted ELF
    allows remote attackers to cause a denial of service, as demonstrated by ld. (CVE-2018-18606)

  - An issue was discovered in elf_link_input_bfd in elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31. There is a NULL pointer dereference in
    elf_link_input_bfd when used for finding STT_TLS symbols without any TLS section. A specially crafted ELF
    allows remote attackers to cause a denial of service, as demonstrated by ld. (CVE-2018-18607)

  - An issue was discovered in cp-demangle.c in GNU libiberty, as distributed in GNU Binutils 2.31. There is a
    stack consumption vulnerability resulting from infinite recursion in the functions d_name(), d_encoding(),
    and d_local_name() in cp-demangle.c. Remote attackers could leverage this vulnerability to cause a denial-
    of-service via an ELF file, as demonstrated by nm. (CVE-2018-18700)

  - An issue was discovered in cp-demangle.c in GNU libiberty, as distributed in GNU Binutils 2.31. There is a
    stack consumption vulnerability resulting from infinite recursion in the functions next_is_type_qual() and
    cplus_demangle_type() in cp-demangle.c. Remote attackers could leverage this vulnerability to cause a
    denial-of-service via an ELF file, as demonstrated by nm. (CVE-2018-18701)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils through 2.31. There is a heap-based buffer overflow in bfd_elf32_swap_phdr_in in elfcode.h
    because the number of program headers is not restricted. (CVE-2018-19931)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils through 2.31. There is an integer overflow and infinite loop caused by the IS_CONTAINED_BY_LMA
    macro in elf.c. (CVE-2018-19932)

  - The _bfd_generic_read_minisymbols function in syms.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.31, has a memory leak via a crafted ELF file, leading to a
    denial of service (memory consumption), as demonstrated by nm. (CVE-2018-20002)

  - In GNU Binutils 2.31.1, there is a use-after-free in the error function in elfcomm.c when called from the
    process_archive function in readelf.c via a crafted ELF file. (CVE-2018-20623)

  - load_specific_debug_section in objdump.c in GNU Binutils through 2.31.1 contains an integer overflow
    vulnerability that can trigger a heap-based buffer overflow via a crafted section size. (CVE-2018-20671)

  - binutils version 2.32 and earlier contains a Integer Overflow vulnerability in objdump,
    bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc that can result in Integer overflow
    trigger heap overflow. Successful exploitation allows execution of arbitrary code.. This attack appear to
    be exploitable via Local. This vulnerability appears to have been fixed in after commit
    3a551c7a1b80fca579461774860574eabfd7f18f. (CVE-2018-1000876)

  - An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.32. It is a heap-based buffer
    over-read in d_expression_1 in cp-demangle.c after many recursive calls. (CVE-2019-9070)

  - An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.32. It is a stack consumption
    issue in d_count_templates_scopes in cp-demangle.c after many recursive calls. (CVE-2019-9071)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an attempted excessive memory allocation in _bfd_elf_slurp_version_tables in elf.c.
    (CVE-2019-9073)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an out-of-bounds read leading to a SEGV in bfd_getl32 in libbfd.c, when called from
    pex64_get_runtime_function in pei-x86_64.c. (CVE-2019-9074)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is a heap-based buffer overflow in _bfd_archive_64_bit_slurp_armap in archive64.c.
    (CVE-2019-9075)

  - An issue was discovered in GNU Binutils 2.32. It is a heap-based buffer overflow in process_mips_specific
    in readelf.c via a malformed MIPS option section. (CVE-2019-9077)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. There is a heap-based buffer over-read in _bfd_doprnt in bfd.c because elf_object_p in
    elfcode.h mishandles an e_shstrndx section of type SHT_GROUP by omitting a trailing '\0' character.
    (CVE-2019-12972)

  - An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.32. simple_object_elf_match in
    simple-object-elf.c does not check for a zero shstrndx value, leading to an integer overflow and resultant
    heap-based buffer overflow. (CVE-2019-14250)

  - apply_relocations in readelf.c in GNU Binutils 2.32 contains an integer overflow that allows attackers to
    trigger a write access violation (in byte_put_little_endian function in elfcomm.c) via an ELF file, as
    demonstrated by readelf. (CVE-2019-14444)

  - find_abstract_instance in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.32, allows remote attackers to cause a denial of service (infinite recursion
    and application crash) via a crafted ELF file. (CVE-2019-17450)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an integer overflow leading to a SEGV in _bfd_dwarf2_find_nearest_line in dwarf2.c,
    as demonstrated by nm. (CVE-2019-17451)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4336-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12699");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-aarch64-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-alpha-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-arm-linux-gnueabihf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-hppa-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-m68k-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mips64el-linux-gnuabi64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-mipsel-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-s390x-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-sh4-linux-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-source");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'binutils', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-aarch64-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-alpha-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabi', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-arm-linux-gnueabihf', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-hppa-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-m68k-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-mips-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-mips64-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-mips64el-linux-gnuabi64', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-mipsel-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-multiarch-dev', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-s390x-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-sh4-linux-gnu', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'},
    {'osver': '16.04', 'pkgname': 'binutils-source', 'pkgver': '2.26.1-1ubuntu1~16.04.8+esm1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-aarch64-linux-gnu / binutils-alpha-linux-gnu / etc');
}
