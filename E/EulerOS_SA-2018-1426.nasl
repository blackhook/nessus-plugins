#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119915);
  script_version("1.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7642",
    "CVE-2018-8945",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535"
  );

  script_name(english:"EulerOS 2.0 SP2 : binutils (EulerOS-SA-2018-1426)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - binutils: integer overflow via an ELF file with corrupt
    dwarf1 debug information in libbfd library
    (CVE-2018-7568)

  - binutils: integer underflow or overflow via an ELF file
    with a corrupt DWARF FORM block in libbfd library
    (CVE-2018-7569)

  - binutils: NULL pointer dereference in swap_std_reloc_in
    function in aoutx.h resulting in crash (CVE-2018-7642)

  - binutils: Crash in elf.c:bfd_section_from_shdr() with
    crafted executable (CVE-2018-8945)

  - binutils: Heap-base buffer over-read in
    dwarf.c:process_cu_tu_index() allows for denial of
    service via crafted file (CVE-2018-10372)

  - binutils: NULL pointer dereference in
    dwarf2.c:concat_filename() allows for denial of service
    via crafted file (CVE-2018-10373)

  - binutils: out of bounds memory write in peXXigen.c
    files (CVE-2018-10534)

  - binutils: NULL pointer dereference in elf.c
    (CVE-2018-10535)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1426
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9d4c1df");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8945");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["binutils-2.25.1-22.base.h14",
        "binutils-devel-2.25.1-22.base.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
