#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135628);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12451",
    "CVE-2017-12452",
    "CVE-2017-12799",
    "CVE-2017-12967",
    "CVE-2017-13710",
    "CVE-2017-14128",
    "CVE-2017-14129",
    "CVE-2017-14529",
    "CVE-2017-14930",
    "CVE-2017-14932",
    "CVE-2017-14934",
    "CVE-2017-14938",
    "CVE-2017-14939",
    "CVE-2017-14940",
    "CVE-2017-15021",
    "CVE-2017-15022",
    "CVE-2017-15024",
    "CVE-2017-15025",
    "CVE-2017-15225",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-15996",
    "CVE-2017-16832",
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17122",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2017-7209",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7302",
    "CVE-2017-7303",
    "CVE-2017-7304",
    "CVE-2017-7614",
    "CVE-2017-8393",
    "CVE-2017-8394",
    "CVE-2017-8395",
    "CVE-2017-8396",
    "CVE-2017-8397",
    "CVE-2017-8398",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9040",
    "CVE-2017-9041",
    "CVE-2017-9042",
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
    "CVE-2017-9955",
    "CVE-2018-12697",
    "CVE-2018-17358",
    "CVE-2018-17359",
    "CVE-2018-17360",
    "CVE-2018-18483",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-19931",
    "CVE-2018-20657",
    "CVE-2018-6323",
    "CVE-2019-1010180",
    "CVE-2019-1010204",
    "CVE-2019-12972",
    "CVE-2019-14250",
    "CVE-2019-17451",
    "CVE-2019-9070",
    "CVE-2019-9071",
    "CVE-2019-9074",
    "CVE-2019-9075",
    "CVE-2019-9076"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : binutils (EulerOS-SA-2020-1466)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - GNU Binutils 2017-04-03 allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash), related to the
    process_mips_specific function in readelf.c, via a
    crafted ELF file that triggers a large
    memory-allocation attempt.(CVE-2017-9040)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has an
    aout_link_add_symbols function in bfd/aoutx.h that is
    vulnerable to a heap-based buffer over-read
    (off-by-one) because of an incomplete check for invalid
    string offsets while loading symbols, leading to a GNU
    linker (ld) program crash.(CVE-2017-7300)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has an
    aout_link_add_symbols function in bfd/aoutx.h that has
    an off-by-one vulnerability because it does not
    carefully check the string offset. The vulnerability
    could lead to a GNU linker (ld) program
    crash.(CVE-2017-7301)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has a
    swap_std_reloc_out function in bfd/aoutx.h that is
    vulnerable to an invalid read (of size 4) because of
    missing checks for relocs that could not be recognised.
    This vulnerability causes Binutils utilities like strip
    to crash.(CVE-2017-7302)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read (of size 4) because of missing a check
    (in the find_link function) for null headers before
    attempting to match them. This vulnerability causes
    Binutils utilities like strip to crash.(CVE-2017-7303)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read (of size 8) because of missing a check
    (in the copy_special_section_fields function) for an
    invalid sh_link field before attempting to follow it.
    This vulnerability causes Binutils utilities like strip
    to crash.(CVE-2017-7304)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to a
    global buffer over-read error because of an assumption
    made by code that runs for objcopy and strip, that
    SHT_REL/SHR_RELA sections are always named starting
    with a .rel/.rela prefix. This vulnerability causes
    programs that conduct an analysis of binary programs
    using the libbfd library, such as objcopy and strip, to
    crash.(CVE-2017-8393)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid write of size 8 because of missing a
    malloc() return-value check to see if memory had
    actually been allocated in the
    _bfd_generic_get_section_contents function. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objcopy, to crash.(CVE-2017-8395)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 1 because the existing reloc
    offset range tests didn't catch small negative offsets
    less than the size of the reloc field. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objdump, to crash.(CVE-2017-8396)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 1 and an invalid write of size
    1 during processing of a corrupt binary containing
    reloc(s) with negative addresses. This vulnerability
    causes programs that conduct an analysis of binary
    programs using the libbfd library, such as objdump, to
    crash.(CVE-2017-8397)

  - dwarf.c in GNU Binutils 2.28 is vulnerable to an
    invalid read of size 1 during dumping of debug
    information from a corrupt binary. This vulnerability
    causes programs that conduct an analysis of binary
    programs, such as objdump and readelf, to
    crash.(CVE-2017-8398)

  - find_abstract_instance_name in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (infinite
    recursion and application crash) via a crafted ELF
    file.(CVE-2017-15024)

  - The setup_group function in elf.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a group section that is too
    small.(CVE-2017-13710)

  - The elf_read_notesfunction in bfd/elf.c in GNU Binutils
    2.29 allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file.(CVE-2017-12799)

  - elfcomm.c in readelf in GNU Binutils 2.29 allows remote
    attackers to cause a denial of service (excessive
    memory allocation) or possibly have unspecified other
    impact via a crafted ELF file that triggers a 'buffer
    overflow on fuzzed archive header,' related to an
    uninitialized variable, an improper conditional jump,
    and the get_archive_member_name,
    process_archive_index_and_symbols, and setup_archive
    functions.(CVE-2017-15996)

  - readelf.c in GNU Binutils 2017-04-12 has a 'cannot be
    represented in type long' issue, which might allow
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted ELF file.(CVE-2017-9042)

  - The score_opcodes function in opcodes/score7-dis.c in
    GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of
    this file during 'objdump -D' execution.(CVE-2017-9742)

  - The sh_elf_set_mach_from_flags function in
    bfd/elf32-sh.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.28, allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file during 'objdump -D' execution.(CVE-2017-9744)

  - The disassemble_bytes function in objdump.c in GNU
    Binutils 2.28 allows remote attackers to cause a denial
    of service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of rae
    insns printing for this file during 'objdump -D'
    execution.(CVE-2017-9746)

  - The ieee_archive_p function in bfd/ieee.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution. NOTE: this may be related to a compiler
    bug.(CVE-2017-9747)

  - The ieee_object_p function in bfd/ieee.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, might allow remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution. NOTE: this may be related to a compiler
    bug.(CVE-2017-9748)

  - The *regs* macros in opcodes/bfin-dis.c in GNU Binutils
    2.28 allow remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file during 'objdump -D' execution.(CVE-2017-9749)

  - opcodes/rx-decode.opc in GNU Binutils 2.28 lacks bounds
    checks for certain scale arrays, which allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9750)

  - opcodes/rl78-decode.opc in GNU Binutils 2.28 has an
    unbounded GETBYTE macro, which allows remote attackers
    to cause a denial of service (buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by
    mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9751)

  - bfd/vms-alpha.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.28, allows remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of this
    file in the _bfd_vms_get_value and _bfd_vms_slurp_etir
    functions during 'objdump -D' execution.(CVE-2017-9752)

  - The versados_mkobject function in bfd/versados.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, does not initialize a
    certain data structure, which allows remote attackers
    to cause a denial of service (buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by
    mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9753)

  - The process_otr function in bfd/versados.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, does not validate a
    certain offset, which allows remote attackers to cause
    a denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of
    this file during 'objdump -D' execution.(CVE-2017-9754)

  - opcodes/i386-dis.c in GNU Binutils 2.28 does not
    consider the number of registers for bnd mode, which
    allows remote attackers to cause a denial of service
    (buffer overflow and application crash) or possibly
    have unspecified other impact via a crafted binary
    file, as demonstrated by mishandling of this file
    during 'objdump -D' execution.(CVE-2017-9755)

  - The aarch64_ext_ldst_reglist function in
    opcodes/aarch64-dis.c in GNU Binutils 2.28 allows
    remote attackers to cause a denial of service (buffer
    overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during
    'objdump -D' execution.(CVE-2017-9756)

  - The elf_object_p function in elfcode.h in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, has an unsigned
    integer overflow because bfd_size_type multiplication
    is not used. A crafted ELF file allows remote attackers
    to cause a denial of service (application crash) or
    possibly have unspecified other impact.(CVE-2018-6323)

  - elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.28, has
    a 'member access within null pointer' undefined
    behavior issue, which might allow remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via an 'int
    main() {return 0}' program.(CVE-2017-7614)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is a heap-based buffer overflow in
    _bfd_archive_64_bit_slurp_armap in
    archive64.c.(CVE-2019-9075)

  - A NULL pointer dereference (aka SEGV on unknown address
    0x000000000000) was discovered in
    work_stuff_copy_to_from in cplus-dem.c in GNU
    libiberty, as distributed in GNU Binutils 2.30. This
    can occur during execution of objdump.(CVE-2018-12697)

  - The bfd_mach_o_i386_canonicalize_one_reloc function in
    bfd/mach-o-i386.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.29 and earlier, allows remote attackers to cause an
    out of bounds heap read via a crafted mach-o
    file.(CVE-2017-12452)

  - GNU binutils gold gold v1.11-v1.16 (GNU binutils
    v2.21-v2.31.1) is affected by: Improper Input
    Validation, Signed/Unsigned Comparison, Out-of-bounds
    Read. The impact is: Denial of service. The component
    is: gold/fileread.cc:497, elfcpp/elfcpp_file.h:644. The
    attack vector is: An ELF file with an invalid e_shoff
    header field must be opened.(CVE-2019-1010204)

  - The _bfd_xcoff_read_ar_hdr function in
    bfd/coff-rs6000.c and bfd/coff64-rs6000.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows
    remote attackers to cause an out of bounds stack read
    via a crafted COFF image file.(CVE-2017-12451)

  - The dump_relocs_in_section function in objdump.c in GNU
    Binutils 2.29.1 does not check for reloc count integer
    overflows, which allows remote attackers to cause a
    denial of service (excessive memory allocation, or
    heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted PE
    file.(CVE-2017-17122)

  - The _bfd_coff_read_string_table function in coffgen.c
    in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, does
    not properly validate the size of the external string
    table, which allows remote attackers to cause a denial
    of service (excessive memory consumption, or heap-based
    buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted COFF
    binary.(CVE-2017-17124)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (memory access
    violation) or possibly have unspecified other impact
    via a COFF binary in which a relocation refers to a
    location after the end of the to-be-relocated
    section.(CVE-2017-17121)

  - nm.c and objdump.c in GNU Binutils 2.29.1 mishandle
    certain global symbols, which allows remote attackers
    to cause a denial of service
    (_bfd_elf_get_symbol_version_string buffer over-read
    and application crash) or possibly have unspecified
    other impact via a crafted ELF file.(CVE-2017-17125)

  - The pe_bfd_read_buildid function in peicode.h in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, does not validate
    size and offset values in the data dictionary, which
    allows remote attackers to cause a denial of service
    (segmentation violation and application crash) or
    possibly have unspecified other impact via a crafted PE
    file.(CVE-2017-16832)

  - dwarf2.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29,
    miscalculates DW_FORM_ref_addr die refs in the case of
    a relocatable object file, which allows remote
    attackers to cause a denial of service
    (find_abstract_instance_name invalid memory read,
    segmentation fault, and application
    crash).(CVE-2017-15938)

  - The _bfd_vms_slurp_etir function in bfd/vms-alpha.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9745)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 4 due to NULL pointer
    dereferencing of _bfd_elf_large_com_section. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objcopy, to crash.(CVE-2017-8394)

  - The getsym function in tekhex.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (stack-based buffer over-read and
    application crash) via a malformed tekhex
    binary.(CVE-2017-12967)

  - The getvalue function in tekhex.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.28, allows remote attackers to cause
    a denial of service (stack-based buffer over-read and
    application crash) via a crafted tekhex file, as
    demonstrated by mishandling within the nm
    program.(CVE-2017-9954)

  - The get_build_id function in opncls.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.28, allows remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) via a crafted
    file in which a certain size field is larger than a
    corresponding data field, as demonstrated by
    mishandling within the objdump program.(CVE-2017-9955)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to
    MIPS GOT mishandling in the process_mips_specific
    function in readelf.c.(CVE-2017-9041)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to
    the byte_get_little_endian function in elfcomm.c, the
    get_unwind_section_word function in readelf.c, and ARM
    unwind information that contains invalid word
    offsets.(CVE-2017-9038)

  - The dump_section_as_bytes function in readelf in GNU
    Binutils 2.28 accesses a NULL pointer while reading
    section contents in a corrupt binary, leading to a
    program crash.(CVE-2017-7209)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has an invalid
    read (of size 8) because the code to emit relocs
    (bfd_elf_final_link function in bfd/elflink.c) does not
    check the format of the input file before trying to
    read the ELF reloc section header. The vulnerability
    leads to a GNU linker (ld) program
    crash.(CVE-2017-7299)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. a heap-based buffer over-read in
    bfd_getl32 in libbfd.c allows an attacker to cause a
    denial of service through a crafted PE file. This
    vulnerability can be triggered by the executable
    objdump.(CVE-2018-17360)

  - The coff_slurp_reloc_table function in coffcode.h in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted COFF
    based file.(CVE-2017-17123)

  - elf.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, does
    not validate sizes of core notes, which allows remote
    attackers to cause a denial of service (bfd_getl32
    heap-based buffer over-read and application crash) via
    a crafted object file, related to
    elfcore_grok_netbsd_procinfo,
    elfcore_grok_openbsd_procinfo, and
    elfcore_grok_nto_status.(CVE-2017-17080)

  - _bfd_dwarf2_cleanup_debug_info in dwarf2.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (memory leak)
    via a crafted ELF file.(CVE-2017-15225)

  - process_debug_info in dwarf.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (infinite loop) via a crafted ELF
    file that contains a negative size value in a CU
    structure.(CVE-2017-14934)

  - dwarf2.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29,
    mishandles NULL files in a .debug_line file table,
    which allows remote attackers to cause a denial of
    service (NULL pointer dereference and application
    crash) via a crafted ELF file, related to
    concat_filename. NOTE: this issue is caused by an
    incomplete fix for CVE-2017-15023.(CVE-2017-15939)

  - decode_line_info in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (infinite loop) via a crafted ELF
    file.(CVE-2017-14932)

  - dwarf2.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29, does
    not validate the DW_AT_name data type, which allows
    remote attackers to cause a denial of service
    (bfd_hash_hash NULL pointer dereference, or
    out-of-bounds access, and application crash) via a
    crafted ELF file, related to scan_unit_for_symbols and
    parse_comp_unit.(CVE-2017-15022)

  - bfd_get_debug_link_info_1 in opncls.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) via a crafted
    ELF file, related to bfd_getl32.(CVE-2017-15021)

  - Memory leak in decode_line_info in dwarf2.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (memory
    consumption) via a crafted ELF file.(CVE-2017-14930)

  - decode_line_info in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (divide-by-zero error and
    application crash) via a crafted ELF
    file.(CVE-2017-15025)

  - decode_line_info in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, mishandles a length calculation,
    which allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted ELF file, related to
    read_1_byte.(CVE-2017-14939)

  - scan_unit_for_symbols in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a crafted ELF
    file.(CVE-2017-14940)

  - _bfd_elf_slurp_version_tables in elf.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (excessive
    memory allocation and application crash) via a crafted
    ELF file.(CVE-2017-14938)

  - The pe_print_idata function in peXXigen.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, mishandles HintName
    vector entries, which allows remote attackers to cause
    a denial of service (heap-based buffer over-read and
    application crash) via a crafted PE file, related to
    the bfd_getl16 function.(CVE-2017-14529)

  - The decode_line_info function in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (read_1_byte
    heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-14128)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (memory consumption) via a crafted
    ELF file with many program headers, related to the
    get_program_headers function in
    readelf.c.(CVE-2017-9039)

  - An issue was discovered in elf_link_input_bfd in
    elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    elf_link_input_bfd when used for finding STT_TLS
    symbols without any TLS section. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18607)

  - An issue was discovered in the merge_strings function
    in merge.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    _bfd_add_merge_section when attempting to merge
    sections with large alignments. A specially crafted ELF
    allows remote attackers to cause a denial of service,
    as demonstrated by ld.(CVE-2018-18606)

  - A heap-based buffer over-read issue was discovered in
    the function sec_merge_hash_lookup in merge.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.31, because
    _bfd_add_merge_section mishandles section merges when
    size is not a multiple of entsize. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18605)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an integer overflow leading to a
    SEGV in _bfd_dwarf2_find_nearest_line in dwarf2.c, as
    demonstrated by nm.(CVE-2019-17451)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. There is a heap-based buffer over-read
    in _bfd_doprnt in bfd.c because elf_object_p in
    elfcode.h mishandles an e_shstrndx section of type
    SHT_GROUP by omitting a trailing '\0'
    character.(CVE-2019-12972)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils through 2.31. There is a heap-based buffer
    overflow in bfd_elf32_swap_phdr_in in elfcode.h because
    the number of program headers is not
    restricted.(CVE-2018-19931)

  - GNU gdb All versions is affected by: Buffer Overflow -
    Out of bound memory access. The impact is: Deny of
    Service, Memory Disclosure, and Possible Code
    Execution. The component is: The main gdb module. The
    attack vector is: Open an ELF for debugging. The fixed
    version is: Not fixed yet.(CVE-2019-1010180)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory access exists in
    bfd_zalloc in opncls.c. Attackers could leverage this
    vulnerability to cause a denial of service (application
    crash) via a crafted ELF file.(CVE-2018-17359)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory access exists in
    _bfd_stab_section_find_nearest_line in syms.c.
    Attackers could leverage this vulnerability to cause a
    denial of service (application crash) via a crafted ELF
    file.(CVE-2018-17358)

  - The read_section function in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (parse_comp_unit
    heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-14129)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an attempted excessive memory
    allocation in elf_read_notes in elf.c.(CVE-2019-9076)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an out-of-bounds read leading to a
    SEGV in bfd_getl32 in libbfd.c, when called from
    pex64_get_runtime_function in
    pei-x86_64.c.(CVE-2019-9074)

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32.
    simple_object_elf_match in simple-object-elf.c does not
    check for a zero shstrndx value, leading to an integer
    overflow and resultant heap-based buffer
    overflow.(CVE-2019-14250)

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32. It is a stack
    consumption issue in d_count_templates_scopes in
    cp-demangle.c after many recursive calls(CVE-2019-9071)

  - An issue was discovered in GNU libiberty, as
    distributed in GNU Binutils 2.32. It is a heap-based
    buffer over-read in d_expression_1 in cp-demangle.c
    after many recursive calls.(CVE-2019-9070)

  - The demangle_template function in cplus-dem.c in GNU
    libiberty, as distributed in GNU Binutils 2.31.1, has a
    memory leak via a crafted string, leading to a denial
    of service (memory consumption), as demonstrated by
    cxxfilt, a related issue to
    CVE-2018-12698.(CVE-2018-20657)

  - The get_count function in cplus-dem.c in GNU libiberty,
    as distributed in GNU Binutils 2.31, allows remote
    attackers to cause a denial of service (malloc called
    with the result of an integer-overflowing calculation)
    or possibly have unspecified other impact via a crafted
    string, as demonstrated by c++filt.(CVE-2018-18483)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1466
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00bc140a");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["binutils-2.27-28.base.1.h40.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
