#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131604);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9939",
    "CVE-2017-12449",
    "CVE-2017-12451",
    "CVE-2017-12452",
    "CVE-2017-12453",
    "CVE-2017-12454",
    "CVE-2017-12455",
    "CVE-2017-12456",
    "CVE-2017-12457",
    "CVE-2017-12458",
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
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17122",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-6969",
    "CVE-2017-7210",
    "CVE-2017-7223",
    "CVE-2017-7224",
    "CVE-2017-7225",
    "CVE-2017-7226",
    "CVE-2017-7227",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7614",
    "CVE-2017-8394",
    "CVE-2017-8395",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9041",
    "CVE-2017-9745",
    "CVE-2017-9750",
    "CVE-2017-9751",
    "CVE-2017-9755",
    "CVE-2017-9954",
    "CVE-2018-14038",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-20002",
    "CVE-2018-6759",
    "CVE-2018-9138",
    "CVE-2019-1010204",
    "CVE-2019-9074"
  );

  script_name(english:"EulerOS 2.0 SP2 : binutils (EulerOS-SA-2019-2450)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in cplus-dem.c in GNU
    libiberty, as distributed in GNU Binutils 2.29 and
    2.30. Stack Exhaustion occurs in the C++ demangling
    functions provided by libiberty, and there are
    recursive stack frames: demangle_nested_args,
    demangle_args, do_arg, and do_type.(CVE-2018-9138)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid write of size 8 because of missing a
    malloc() return-value check to see if memory had
    actually been allocated in the
    _bfd_generic_get_section_contents function. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objcopy, to crash.(CVE-2017-8395)

  - _bfd_elf_slurp_version_tables in elf.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (excessive
    memory allocation and application crash) via a crafted
    ELF file.(CVE-2017-14938)

  - opcodes/rl78-decode.opc in GNU Binutils 2.28 has an
    unbounded GETBYTE macro, which allows remote attackers
    to cause a denial of service (buffer overflow and
    application crash) or possibly have unspecified other
    impact via a crafted binary file, as demonstrated by
    mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9751)

  - elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.28, has
    a 'member access within null pointer' undefined
    behavior issue, which might allow remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via an 'int
    main() {return 0}' program.(CVE-2017-7614)

  - A heap-based buffer over-read issue was discovered in
    the function sec_merge_hash_lookup in merge.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.31, because
    _bfd_add_merge_section mishandles section merges when
    size is not a multiple of entsize. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18605)

  - An issue was discovered in the merge_strings function
    in merge.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    _bfd_add_merge_section when attempting to merge
    sections with large alignments. A specially crafted ELF
    allows remote attackers to cause a denial of service,
    as demonstrated by ld.(CVE-2018-18606)

  - An issue was discovered in elf_link_input_bfd in
    elflink.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.31.
    There is a NULL pointer dereference in
    elf_link_input_bfd when used for finding STT_TLS
    symbols without any TLS section. A specially crafted
    ELF allows remote attackers to cause a denial of
    service, as demonstrated by ld.(CVE-2018-18607)

  - The _bfd_generic_read_minisymbols function in syms.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.31, has a memory leak
    via a crafted ELF file, leading to a denial of service
    (memory consumption), as demonstrated by
    nm.(CVE-2018-20002)

  - The decode_line_info function in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (read_1_byte
    heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-14128)

  - decode_line_info in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, mishandles a length calculation,
    which allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application
    crash) via a crafted ELF file, related to
    read_1_byte.(CVE-2017-14939)

  - An issue was discovered in the Binary File Descriptor
    (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an out-of-bounds read leading to a
    SEGV in bfd_getl32 in libbfd.c, when called from
    pex64_get_runtime_function in
    pei-x86_64.c.(CVE-2019-9074)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, has an invalid
    read (of size 8) because the code to emit relocs
    (bfd_elf_final_link function in bfd/elflink.c) does not
    check the format of the input file before trying to
    read the ELF reloc section header. The vulnerability
    leads to a GNU linker (ld) program
    crash.(CVE-2017-7299)

  - The setup_group function in elf.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a group section that is too
    small.(CVE-2017-13710)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER.
    ConsultIDs: CVE-2018-7642. Reason: This candidate is a
    reservation duplicate of CVE-2018-7642. Notes: All CVE
    users should reference CVE-2018-7642 instead of this
    candidate. All references and descriptions in this
    candidate have been removed to prevent accidental
    usage.(CVE-2018-14038)

  - The _bfd_vms_save_sized_string function in vms-misc.c
    in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and
    earlier, allows remote attackers to cause an out of
    bounds heap read via a crafted vms
    file.(CVE-2017-12449)

  - The _bfd_xcoff_read_ar_hdr function in
    bfd/coff-rs6000.c and bfd/coff64-rs6000.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows
    remote attackers to cause an out of bounds stack read
    via a crafted COFF image file.(CVE-2017-12451)

  - The bfd_mach_o_i386_canonicalize_one_reloc function in
    bfd/mach-o-i386.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.29 and earlier, allows remote attackers to cause an
    out of bounds heap read via a crafted mach-o
    file.(CVE-2017-12452)

  - The _bfd_vms_slurp_eeom function in libbfd.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows
    remote attackers to cause an out of bounds heap read
    via a crafted vms alpha file.(CVE-2017-12453)

  - The _bfd_vms_slurp_egsd function in bfd/vms-alpha.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29 and earlier, allows
    remote attackers to cause an arbitrary memory read via
    a crafted vms alpha file.(CVE-2017-12454)

  - The evax_bfd_print_emh function in vms-alpha.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29 and earlier, allows
    remote attackers to cause an out of bounds heap read
    via a crafted vms alpha file.(CVE-2017-12455)

  - The read_symbol_stabs_debugging_info function in
    rddbg.c in GNU Binutils 2.29 and earlier allows remote
    attackers to cause an out of bounds heap read via a
    crafted binary file.(CVE-2017-12456)

  - The bfd_make_section_with_flags function in section.c
    in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29 and
    earlier, allows remote attackers to cause a NULL
    dereference via a crafted file.(CVE-2017-12457)

  - The nlm_swap_auxiliary_headers_in function in
    bfd/nlmcode.h in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.29 and earlier, allows remote attackers to cause an
    out of bounds heap read via a crafted nlm
    file.(CVE-2017-12458)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, is vulnerable to
    an invalid read of size 4 due to NULL pointer
    dereferencing of _bfd_elf_large_com_section. This
    vulnerability causes programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objcopy, to crash.(CVE-2017-8394)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to
    MIPS GOT mishandling in the process_mips_specific
    function in readelf.c.(CVE-2017-9041)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (memory consumption) via a crafted
    ELF file with many program headers, related to the
    get_program_headers function in
    readelf.c.(CVE-2017-9039)

  - The getsym function in tekhex.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (stack-based buffer over-read and
    application crash) via a malformed tekhex
    binary.(CVE-2017-12967)

  - ihex.c in GNU Binutils before 2.26 contains a stack
    buffer overflow when printing bad bytes in Intel Hex
    objects.(CVE-2014-9939)

  - GNU Binutils 2.28 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted ELF file, related to
    the byte_get_little_endian function in elfcomm.c, the
    get_unwind_section_word function in readelf.c, and ARM
    unwind information that contains invalid word
    offsets.(CVE-2017-9038)

  - opcodes/rx-decode.opc in GNU Binutils 2.28 lacks bounds
    checks for certain scale arrays, which allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9750)

  - objdump in GNU Binutils 2.28 is vulnerable to multiple
    heap-based buffer over-reads (of size 1 and size 8)
    while handling corrupt STABS enum type strings in a
    crafted object file, leading to program
    crash.(CVE-2017-7210)

  - GNU assembler in GNU Binutils 2.28 is vulnerable to a
    global buffer overflow (of size 1) while attempting to
    unget an EOF character from the input stream,
    potentially leading to a program crash.(CVE-2017-7223)

  - The find_nearest_line function in objdump in GNU
    Binutils 2.28 is vulnerable to an invalid write (of
    size 1) while disassembling a corrupt binary that
    contains an empty function name, leading to a program
    crash.(CVE-2017-7224)

  - The find_nearest_line function in addr2line in GNU
    Binutils 2.28 does not handle the case where the main
    file name and the directory name are both empty,
    triggering a NULL pointer dereference and an invalid
    write, and leading to a program crash.(CVE-2017-7225)

  - The pe_ILF_object_p function in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.28, is vulnerable to a heap-based
    buffer over-read of size 4049 because it uses the
    strlen function instead of strnlen, leading to program
    crashes in several utilities such as addr2line, size,
    and strings. It could lead to information disclosure as
    well.(CVE-2017-7226)

  - GNU linker (ld) in GNU Binutils 2.28 is vulnerable to a
    heap-based buffer overflow while processing a bogus
    input script, leading to a program crash. This relates
    to lack of '\0' termination of a name field in
    ldlex.l.(CVE-2017-7227)

  - opcodes/i386-dis.c in GNU Binutils 2.28 does not
    consider the number of registers for bnd mode, which
    allows remote attackers to cause a denial of service
    (buffer overflow and application crash) or possibly
    have unspecified other impact via a crafted binary
    file, as demonstrated by mishandling of this file
    during 'objdump -D' execution.(CVE-2017-9755)

  - The bfd_get_debug_link_info_1 function in opncls.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.30, has an unchecked
    strnlen operation. Remote attackers could leverage this
    vulnerability to cause a denial of service
    (segmentation fault) via a crafted ELF
    file.(CVE-2018-6759)

  - The read_section function in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (parse_comp_unit
    heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-14129)

  - dwarf2.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.29, does
    not validate the DW_AT_name data type, which allows
    remote attackers to cause a denial of service
    (bfd_hash_hash NULL pointer dereference, or
    out-of-bounds access, and application crash) via a
    crafted ELF file, related to scan_unit_for_symbols and
    parse_comp_unit.(CVE-2017-15022)

  - The coff_slurp_reloc_table function in coffcode.h in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted COFF
    based file.(CVE-2017-17123)

  - The pe_print_idata function in peXXigen.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, mishandles HintName
    vector entries, which allows remote attackers to cause
    a denial of service (heap-based buffer over-read and
    application crash) via a crafted PE file, related to
    the bfd_getl16 function.(CVE-2017-14529)

  - find_abstract_instance_name in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (infinite
    recursion and application crash) via a crafted ELF
    file.(CVE-2017-15024)

  - readelf in GNU Binutils 2.28 is vulnerable to a
    heap-based buffer over-read while processing corrupt
    RL78 binaries. The vulnerability can trigger program
    crashes. It may lead to an information leak as
    well.(CVE-2017-6969)

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
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (infinite loop) via a crafted ELF
    file.(CVE-2017-14932)

  - _bfd_dwarf2_cleanup_debug_info in dwarf2.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (memory leak)
    via a crafted ELF file.(CVE-2017-15225)

  - The _bfd_vms_slurp_etir function in bfd/vms-alpha.c in
    the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.28, allows remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution.(CVE-2017-9745)

  - process_debug_info in dwarf.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (infinite loop) via a crafted ELF
    file that contains a negative size value in a CU
    structure.(CVE-2017-14934)

  - elf.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29.1, does
    not validate sizes of core notes, which allows remote
    attackers to cause a denial of service (bfd_getl32
    heap-based buffer over-read and application crash) via
    a crafted object file, related to
    elfcore_grok_netbsd_procinfo,
    elfcore_grok_openbsd_procinfo, and
    elfcore_grok_nto_status.(CVE-2017-17080)

  - scan_unit_for_symbols in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.29, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a crafted ELF
    file.(CVE-2017-14940)

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.29.1, allows remote
    attackers to cause a denial of service (memory access
    violation) or possibly have unspecified other impact
    via a COFF binary in which a relocation refers to a
    location after the end of the to-be-relocated
    section.(CVE-2017-17121)

  - bfd_get_debug_link_info_1 in opncls.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) via a crafted
    ELF file, related to bfd_getl32.(CVE-2017-15021)

  - The dump_relocs_in_section function in objdump.c in GNU
    Binutils 2.29.1 does not check for reloc count integer
    overflows, which allows remote attackers to cause a
    denial of service (excessive memory allocation, or
    heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted PE
    file.(CVE-2017-17122)

  - The getvalue function in tekhex.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.28, allows remote attackers to cause
    a denial of service (stack-based buffer over-read and
    application crash) via a crafted tekhex file, as
    demonstrated by mishandling within the nm
    program.(CVE-2017-9954)

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

  - GNU binutils gold gold v1.11-v1.16 (GNU binutils
    v2.21-v2.31.1) is affected by: Improper Input
    Validation, Signed/Unsigned Comparison, Out-of-bounds
    Read. The impact is: Denial of service. The component
    is: gold/fileread.cc:497, elfcpp/elfcpp_file.h:644. The
    attack vector is: An ELF file with an invalid e_shoff
    header field must be opened.(CVE-2019-1010204)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2450
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6d75b11");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["binutils-2.25.1-22.base.h43",
        "binutils-devel-2.25.1-22.base.h43"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
