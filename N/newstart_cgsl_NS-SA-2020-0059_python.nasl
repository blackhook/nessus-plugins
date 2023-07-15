##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0059. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143918);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2018-20852", "CVE-2019-16056");
  script_bugtraq_id(109177);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : python Multiple Vulnerabilities (NS-SA-2020-0059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has python packages installed that are affected by
multiple vulnerabilities:

  - http.cookiejar.DefaultPolicy.domain_return_ok in Lib/http/cookiejar.py in Python before 3.7.3 does not
    correctly validate the domain: it can be tricked into sending existing cookies to the wrong server. An
    attacker may abuse this flaw by using a server with a hostname that has another valid hostname as a suffix
    (e.g., pythonicexample.com to steal cookies for example.com). When a program uses
    http.cookiejar.DefaultPolicy and tries to do an HTTP connection to an attacker-controlled server, existing
    cookies can be leaked to the attacker. This affects 2.x through 2.7.16, 3.x before 3.4.10, 3.5.x before
    3.5.7, 3.6.x before 3.6.9, and 3.7.x before 3.7.3. (CVE-2018-20852)

  - An issue was discovered in Python through 2.7.16, 3.x through 3.5.7, 3.6.x through 3.6.9, and 3.7.x
    through 3.7.4. The email module wrongly parses email addresses that contain multiple @ characters. An
    application that uses the email module and implements some kind of checks on the From/To headers of a
    message could be tricked into accepting an email address that should be denied. An attack may be the same
    as in CVE-2019-11340; however, this CVE applies to Python more generally. (CVE-2019-16056)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0059");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'python-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-debug-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-debuginfo-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-devel-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-libs-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-test-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'python-tools-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite',
    'tkinter-2.7.5-88.el7.cgslv5.0.2.g8f0374e.lite'
  ],
  'CGSL MAIN 5.04': [
    'python-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-debug-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-debuginfo-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-devel-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-libs-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-test-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'python-tools-2.7.5-88.el7.cgslv5.0.2.g900d261',
    'tkinter-2.7.5-88.el7.cgslv5.0.2.g900d261'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python');
}
