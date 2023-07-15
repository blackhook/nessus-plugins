#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0035. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127204);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-10194",
    "CVE-2018-15910",
    "CVE-2018-16509",
    "CVE-2018-16542"
  );
  script_bugtraq_id(105122, 105122);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ghostscript Multiple Vulnerabilities (NS-SA-2019-0035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ghostscript packages installed that are
affected by multiple vulnerabilities:

  - The set_text_distance function in
    devices/vector/gdevpdts.c in the pdfwrite component in
    Artifex Ghostscript through 9.22 does not prevent
    overflows in text-positioning calculation, which allows
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted PDF document. (CVE-2018-10194)

  - It was discovered that the type of the
    LockDistillerParams parameter is not properly verified.
    An attacker could possibly exploit this to bypass the
    -dSAFER protection and crash ghostscript or, possibly,
    execute arbitrary code in the ghostscript context via a
    specially crafted PostScript document. (CVE-2018-15910)

  - It was discovered that the ghostscript /invalidaccess
    checks fail under certain conditions. An attacker could
    possibly exploit this to bypass the -dSAFER protection
    and, for example, execute arbitrary shell commands via a
    specially crafted PostScript document. (CVE-2018-16509)

  - It was discovered that ghostscript did not properly
    handle certain stack overflow error conditions. An
    attacker could possibly exploit this to bypass the
    -dSAFER protection and crash ghostscript or, possibly,
    execute arbitrary code in the ghostscript context via a
    specially crafted PostScript document. (CVE-2018-16542)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0035");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ghostscript packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16509");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
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
    "ghostscript-9.07-29.el7_5.2",
    "ghostscript-cups-9.07-29.el7_5.2",
    "ghostscript-debuginfo-9.07-29.el7_5.2",
    "ghostscript-devel-9.07-29.el7_5.2",
    "ghostscript-doc-9.07-29.el7_5.2",
    "ghostscript-gtk-9.07-29.el7_5.2"
  ],
  "CGSL MAIN 5.04": [
    "ghostscript-9.07-29.el7_5.2",
    "ghostscript-cups-9.07-29.el7_5.2",
    "ghostscript-debuginfo-9.07-29.el7_5.2",
    "ghostscript-devel-9.07-29.el7_5.2",
    "ghostscript-doc-9.07-29.el7_5.2",
    "ghostscript-gtk-9.07-29.el7_5.2"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
