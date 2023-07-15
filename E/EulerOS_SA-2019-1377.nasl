#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124880);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : binutils (EulerOS-SA-2019-1377)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - concat_filename in dwarf2.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.30, allows remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a crafted binary file, as
    demonstrated by nm-new.(CVE-2018-10373)

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
    pex64igen.c.(CVE-2018-10534)

  - The parse_die function in dwarf1.c in the Binary File
    Descriptor (BFD) library (aka libbfd), as distributed
    in GNU Binutils 2.30, allows remote attackers to cause
    a denial of service (integer overflow and application
    crash) via an ELF file with corrupt dwarf1 debug
    information, as demonstrated by nm.(CVE-2018-7568)

  - The swap_std_reloc_in function in aoutx.h in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference
    and application crash) via a crafted ELF file, as
    demonstrated by objcopy.(CVE-2018-7642)

  - process_cu_tu_index in dwarf.c in GNU Binutils 2.30
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted binary file, as demonstrated by
    readelf.(CVE-2018-10372)

  - In the coff_pointerize_aux function in coffgen.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, an index is not
    validated, which allows remote attackers to cause a
    denial of service (segmentation fault) or possibly have
    unspecified other impact via a crafted file, as
    demonstrated by objcopy of a COFF
    object.(CVE-2018-7208)

  - The ignore_section_sym function in elf.c in the Binary
    File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, does not validate the
    output_section pointer in the case of a symtab entry
    with a ''SECTION'' type that has a ''0'' value, which
    allows remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via a
    crafted file, as demonstrated by
    objcopy.(CVE-2018-10535)

  - The display_debug_ranges function in dwarf.c in GNU
    Binutils 2.30 allows remote attackers to cause a denial
    of service (integer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    ELF file, as demonstrated by objdump.(CVE-2018-7643)

  - The bfd_section_from_shdr function in elf.c in the
    Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.30, allows remote
    attackers to cause a denial of service (segmentation
    fault) via a large attribute section.(CVE-2018-8945)

  - dwarf2.c in the Binary File Descriptor (BFD) library
    (aka libbfd), as distributed in GNU Binutils 2.30,
    allows remote attackers to cause a denial of service
    (integer underflow or overflow, and application crash)
    via an ELF file with a corrupt DWARF FORM block, as
    demonstrated by nm.(CVE-2018-7569)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1377
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e158241");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["binutils-2.27-28.base.1.h15"];

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
