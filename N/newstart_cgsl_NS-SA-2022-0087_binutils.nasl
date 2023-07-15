#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0087. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167457);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id(
    "CVE-2018-6323",
    "CVE-2018-6759",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7570",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-17358",
    "CVE-2018-20002",
    "CVE-2020-35448",
    "CVE-2021-3487",
    "CVE-2021-20197",
    "CVE-2021-20284",
    "CVE-2021-42574"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : binutils Multiple Vulnerabilities (NS-SA-2022-0087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has binutils packages installed that are affected by multiple
vulnerabilities:

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

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.31. An invalid memory access exists in _bfd_stab_section_find_nearest_line in syms.c. Attackers
    could leverage this vulnerability to cause a denial of service (application crash) via a crafted ELF file.
    (CVE-2018-17358)

  - The _bfd_generic_read_minisymbols function in syms.c in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.31, has a memory leak via a crafted ELF file, leading to a
    denial of service (memory consumption), as demonstrated by nm. (CVE-2018-20002)

  - The elf_object_p function in elfcode.h in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.29.1, has an unsigned integer overflow because bfd_size_type multiplication
    is not used. A crafted ELF file allows remote attackers to cause a denial of service (application crash)
    or possibly have unspecified other impact. (CVE-2018-6323)

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

  - The assign_file_positions_for_non_load_sections function in elf.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils 2.30, allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash) via an ELF file with a RELRO segment that lacks a
    matching LOAD segment, as demonstrated by objcopy. (CVE-2018-7570)

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

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.35.1. A heap-based buffer over-read can occur in bfd_getl_signed_32 in libbfd.c because
    sh_entsize is not validated in _bfd_elf_slurp_secondary_reloc_section in elf.c. (CVE-2020-35448)

  - There is an open race window when writing output in the following utilities in GNU binutils version 2.35
    and earlier:ar, objcopy, strip, ranlib. When these utilities are run as a privileged user (presumably as
    part of a script updating binaries across different users), an unprivileged user can trick these utilities
    into getting ownership of arbitrary files through a symlink. (CVE-2021-20197)

  - A flaw was found in GNU Binutils 2.35.1, where there is a heap-based buffer overflow in
    _bfd_elf_slurp_secondary_reloc_section in elf.c due to the number of symbols not calculated correctly. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20284)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0087");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-10372");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-10373");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-10534");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-10535");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-17358");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-20002");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-6323");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-6759");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7208");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7568");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7569");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7570");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7642");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-7643");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-8945");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-35448");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20197");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20284");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3487");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-42574");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL binutils packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'binutils-2.32-17.el8_1.cgslv6_2',
    'binutils-devel-2.32-17.el8_1.cgslv6_2'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils');
}
