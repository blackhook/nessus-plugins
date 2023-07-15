#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0203. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(129908);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/05");

  script_cve_id(
    "CVE-2018-11645",
    "CVE-2019-10216",
    "CVE-2019-14811",
    "CVE-2019-14812",
    "CVE-2019-14813",
    "CVE-2019-14817"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ghostscript Multiple Vulnerabilities (NS-SA-2019-0203)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ghostscript packages installed that are
affected by multiple vulnerabilities:

  - psi/zfile.c in Artifex Ghostscript before 9.21rc1
    permits the status command even if -dSAFER is used,
    which might allow remote attackers to determine the
    existence and size of arbitrary files, a similar issue
    to CVE-2016-7977. (CVE-2018-11645)

  - A flaw was found in ghostscript, versions 9.x before
    9.28, in the setsystemparams procedure where it did not
    properly secure its privileged calls, enabling scripts
    to bypass `-dSAFER` restrictions. A specially crafted
    PostScript file could disable security protection and
    then have access to the file system, or execute
    arbitrary commands. (CVE-2019-14813)

  - A flaw was found in, ghostscript versions prior to 9.28,
    in the .pdf_hook_DSC_Creator procedure where it did not
    properly secure its privileged calls, enabling scripts
    to bypass `-dSAFER` restrictions. A specially crafted
    PostScript file could disable security protection and
    then have access to the file system, or execute
    arbitrary commands. (CVE-2019-14811)

  - A flaw was found in, ghostscript versions prior to 9.28,
    in the .pdfexectoken and other procedures where it did
    not properly secure its privileged calls, enabling
    scripts to bypass `-dSAFER` restrictions. A specially
    crafted PostScript file could disable security
    protection and then have access to the file system, or
    execute arbitrary commands. (CVE-2019-14817)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0203");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ghostscript packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    "ghostscript-9.25-2.el7_7.2",
    "ghostscript-cups-9.25-2.el7_7.2",
    "ghostscript-debuginfo-9.25-2.el7_7.2",
    "ghostscript-doc-9.25-2.el7_7.2",
    "ghostscript-gtk-9.25-2.el7_7.2",
    "libgs-9.25-2.el7_7.2",
    "libgs-devel-9.25-2.el7_7.2"
  ],
  "CGSL MAIN 5.04": [
    "ghostscript-9.25-2.el7_7.2",
    "ghostscript-cups-9.25-2.el7_7.2",
    "ghostscript-debuginfo-9.25-2.el7_7.2",
    "ghostscript-doc-9.25-2.el7_7.2",
    "ghostscript-gtk-9.25-2.el7_7.2",
    "libgs-9.25-2.el7_7.2",
    "libgs-devel-9.25-2.el7_7.2"
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
