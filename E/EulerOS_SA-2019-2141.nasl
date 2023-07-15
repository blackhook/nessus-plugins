#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130850);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-16403",
    "CVE-2018-18521",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7665"
  );

  script_name(english:"EulerOS 2.0 SP5 : elfutils (EulerOS-SA-2019-2141)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the elfutils packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - dwarf_getaranges in dwarf_getaranges.c in libdw in
    elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read)
    via a crafted file.(CVE-2018-16062)

  - dwarf_getaranges in dwarf_getaranges.c in libdw in
    elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read)
    via a crafted file.(CVE-2018-16402)

  - libdw in elfutils 0.173 checks the end of the
    attributes list incorrectly in dwarf_getabbrev in
    dwarf_getabbrev.c and dwarf_hasattr in dwarf_hasattr.c,
    leading to a heap-based buffer over-read and an
    application crash.(CVE-2018-16403)

  - Divide-by-zero vulnerabilities in the function
    arlib_add_symbols() in arlib.c in elfutils 0.174 allow
    remote attackers to cause a denial of service
    (application crash) with a crafted ELF file, as
    demonstrated by eu-ranlib, because a zero sh_entsize is
    mishandled.(CVE-2018-18521)

  - A heap-based buffer over-read was discovered in the
    function read_srclines in dwarf_getsrclines.c in libdw
    in elfutils 0.175. A crafted input can cause
    segmentation faults, leading to denial-of-service, as
    demonstrated by eu-nm.(CVE-2019-7149)

  - An issue was discovered in elfutils 0.175. A
    segmentation fault can occur in the function
    elf64_xlatetom in libelf/elf32_xlatetom.c, due to
    dwfl_segment_report_module not checking whether the dyn
    data read from a core file is truncated. A crafted
    input can cause a program crash, leading to
    denial-of-service, as demonstrated by
    eu-stack.(CVE-2019-7150)

  - In elfutils 0.175, a heap-based buffer over-read was
    discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can
    cause a segmentation fault leading to denial of service
    (program crash) because ebl_core_note does not reject
    malformed core file notes.(CVE-2019-7665)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2141
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a02caa4b");
  script_set_attribute(attribute:"solution", value:
"Update the affected elfutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-default-yama-scope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:elfutils-libs");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["elfutils-0.170-4.h4.eulerosv2r7",
        "elfutils-default-yama-scope-0.170-4.h4.eulerosv2r7",
        "elfutils-devel-0.170-4.h4.eulerosv2r7",
        "elfutils-libelf-0.170-4.h4.eulerosv2r7",
        "elfutils-libelf-devel-0.170-4.h4.eulerosv2r7",
        "elfutils-libs-0.170-4.h4.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils");
}
