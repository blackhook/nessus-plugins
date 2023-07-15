#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0126. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154597);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2019-14494");
  script_xref(name:"IAVB", value:"2019-B-0064-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : poppler Vulnerability (NS-SA-2021-0126)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has poppler packages installed that are affected by a
vulnerability:

  - An issue was discovered in Poppler through 0.78.0. There is a divide-by-zero error in the function
    SplashOutputDev::tilingPatternFill at SplashOutputDev.cc. (CVE-2019-14494)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0126");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14494");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL poppler packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-cpp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-glib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:poppler-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'poppler-0.66.0-27.el8',
    'poppler-cpp-0.66.0-27.el8',
    'poppler-cpp-debuginfo-0.66.0-27.el8',
    'poppler-cpp-devel-0.66.0-27.el8',
    'poppler-debuginfo-0.66.0-27.el8',
    'poppler-debugsource-0.66.0-27.el8',
    'poppler-devel-0.66.0-27.el8',
    'poppler-glib-0.66.0-27.el8',
    'poppler-glib-debuginfo-0.66.0-27.el8',
    'poppler-glib-devel-0.66.0-27.el8',
    'poppler-glib-doc-0.66.0-27.el8',
    'poppler-qt5-0.66.0-27.el8',
    'poppler-qt5-debuginfo-0.66.0-27.el8',
    'poppler-qt5-devel-0.66.0-27.el8',
    'poppler-utils-0.66.0-27.el8',
    'poppler-utils-debuginfo-0.66.0-27.el8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'poppler');
}
