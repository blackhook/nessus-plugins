#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0060. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127252);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-13033"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : binutils Multiple Vulnerabilities (NS-SA-2019-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has binutils packages installed that are affected
by multiple vulnerabilities:

  - The Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (excessive memory
    allocation and application crash) via a crafted ELF
    file, as demonstrated by _bfd_elf_parse_attributes in
    elf-attrs.c and bfd_malloc in libbfd.c. This can occur
    during execution of nm. (CVE-2018-13033)

  - The _bfd_XX_bfd_copy_private_bfd_data_common function in
    peXXigen.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.30,
    processes a negative Data Directory size with an
    unbounded loop that increases the value of
    (external_IMAGE_DEBUG_DIRECTORY) *edd so that the
    address exceeds its own memory region, resulting in an
    out-of-bounds memory write, as demonstrated by objcopy
    copying private info with
    _bfd_pex64_bfd_copy_private_bfd_data_common in
    pex64igen.c. (CVE-2018-10534)

  - The ignore_section_sym function in elf.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, does not validate the
    output_section pointer in the case of a symtab entry
    with a SECTION type that has a 0 value, which allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and application crash) via a crafted
    file, as demonstrated by objcopy. (CVE-2018-10535)

  - process_cu_tu_index in dwarf.c in GNU Binutils 2.30
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted binary file, as demonstrated by readelf.
    (CVE-2018-10372)

  - concat_filename in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed in
    GNU Binutils 2.30, allows remote attackers to cause a
    denial of service (NULL pointer dereference and
    application crash) via a crafted binary file, as
    demonstrated by nm-new. (CVE-2018-10373)

  - The display_debug_ranges function in dwarf.c in GNU
    Binutils 2.30 allows remote attackers to cause a denial
    of service (integer overflow and application crash) or
    possibly have unspecified other impact via a crafted ELF
    file, as demonstrated by objdump. (CVE-2018-7643)

  - An integer wraparound has been discovered in the Binary
    File Descriptor (BFD) library distributed in GNU
    Binutils up to version 2.30. An attacker could cause a
    crash by providing an ELF file with corrupted DWARF
    debug information. (CVE-2018-7568, CVE-2018-7569)

  - The swap_std_reloc_in function in aoutx.h in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference and
    application crash) via a crafted ELF file, as
    demonstrated by objcopy. (CVE-2018-7642)

  - The bfd_section_from_shdr function in elf.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (segmentation
    fault) via a large attribute section. (CVE-2018-8945)

  - In the coff_pointerize_aux function in coffgen.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, an index is not
    validated, which allows remote attackers to cause a
    denial of service (segmentation fault) or possibly have
    unspecified other impact via a crafted file, as
    demonstrated by objcopy of a COFF object.
    (CVE-2018-7208)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0060");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL binutils packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "binutils-2.27-34.base.el7",
    "binutils-debuginfo-2.27-34.base.el7",
    "binutils-devel-2.27-34.base.el7"
  ],
  "CGSL MAIN 5.04": [
    "binutils-2.27-34.base.el7",
    "binutils-debuginfo-2.27-34.base.el7",
    "binutils-devel-2.27-34.base.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
