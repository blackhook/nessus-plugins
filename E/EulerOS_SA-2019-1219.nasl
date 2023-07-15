#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123905);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2017-14130",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-8945",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535"
  );

  script_name(english:"EulerOS Virtualization 2.5.4 : binutils (EulerOS-SA-2019-1219)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An integer wraparound has been discovered in the Binary
    File Descriptor (BFD) library distributed in GNU
    Binutils up to version 2.30. An attacker could cause a
    crash by providing an ELF file with corrupted DWARF
    debug information.i1/4^CVE-2018-7568i1/4%0

  - An integer wraparound has been discovered in the Binary
    File Descriptor (BFD) library distributed in GNU
    Binutils up to version 2.30. An attacker could cause a
    crash by providing an ELF file with corrupted DWARF
    debug information.i1/4^CVE-2018-7569i1/4%0

  - The swap_std_reloc_in function in aoutx.h in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference
    and application crash) via a crafted ELF file, as
    demonstrated by objcopy.i1/4^CVE-2018-7642i1/4%0

  - The bfd_section_from_shdr function in elf.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (segmentation
    fault) via a large attribute
    section.i1/4^CVE-2018-8945i1/4%0

  - process_cu_tu_index in dwarf.c in GNU Binutils 2.30
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted binary file, as demonstrated by
    readelf.i1/4^CVE-2018-10372i1/4%0

  - concat_filename in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.30, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a crafted binary file, as
    demonstrated by nm-new.i1/4^CVE-2018-10373i1/4%0

  - The _bfd_XX_bfd_copy_private_bfd_data_common function
    in peXXigen.c in the Binary File Descriptor (BFD)
    library (aka libbfd), as distributed in GNU Binutils
    2.30, processes a negative Data Directory size with an
    unbounded loop that increases the value of
    (external_IMAGE_DEBUG_DIRECTORY) *edd so that the
    address exceeds its own memory region, resulting in an
    out-of-bounds memory write, as demonstrated by objcopy
    copying private info with
    _bfd_pex64_bfd_copy_private_bfd_data_common in
    pex64igen.c.i1/4^CVE-2018-10534i1/4%0

  - The ignore_section_sym function in elf.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, does not validate the
    output_section pointer in the case of a symtab entry
    with a 'SECTION' type that has a '0' value, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted file, as demonstrated by
    objcopy.i1/4^CVE-2018-10535i1/4%0

  - The _bfd_elf_parse_attributes function in elf-attrs.c
    in the Binary File Descriptor (BFD) library (aka
    libbfd), as distributed in GNU Binutils 2.29, allows
    remote attackers to cause a denial of service
    (_bfd_elf_attr_strdup heap-based buffer over-read and
    application crash) via a crafted ELF
    file.i1/4^CVE-2017-14130i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1219
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7399cf17");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8945");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.4") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.4");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["binutils-2.27-28.base.1.h11"];

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
