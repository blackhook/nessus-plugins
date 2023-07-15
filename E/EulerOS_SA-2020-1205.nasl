#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134494);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12967",
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
    "CVE-2017-15025",
    "CVE-2017-15225",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-16832",
    "CVE-2017-17080",
    "CVE-2017-17121",
    "CVE-2017-17122",
    "CVE-2017-17123",
    "CVE-2017-17124",
    "CVE-2017-17125",
    "CVE-2017-7209",
    "CVE-2017-7299",
    "CVE-2017-8394",
    "CVE-2017-9038",
    "CVE-2017-9039",
    "CVE-2017-9041",
    "CVE-2017-9745",
    "CVE-2017-9954",
    "CVE-2017-9955",
    "CVE-2018-17358",
    "CVE-2018-17359",
    "CVE-2018-17360",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2019-17451"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : binutils (EulerOS-SA-2020-1205)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

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

  - The read_section function in dwarf2.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29, allows remote
    attackers to cause a denial of service (parse_comp_unit
    heap-based buffer over-read and application crash) via
    a crafted ELF file.(CVE-2017-14129)

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

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1205
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b4b0803");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9745");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["binutils-2.27-28.base.1.h32"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
