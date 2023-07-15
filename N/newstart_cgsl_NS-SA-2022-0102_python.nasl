#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0102. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168928);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id(
    "CVE-2020-26116",
    "CVE-2020-26137",
    "CVE-2021-3177",
    "CVE-2022-0391"
  );
  script_xref(name:"IAVA", value:"2021-A-0052-S");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : python Multiple Vulnerabilities (NS-SA-2022-0102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has python packages installed that are affected by
multiple vulnerabilities:

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

  - urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as
    demonstrated by inserting CR and LF control characters in the first argument of putrequest(). NOTE: this
    is similar to CVE-2020-26116. (CVE-2020-26137)

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

  - A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform
    Resource Locator (URL) strings into components. The issue involves how the urlparse method does not
    sanitize input and allows characters like '\r' and '\n' in the URL path. This flaw allows an attacker to
    input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1,
    3.9.5, 3.8.11, 3.7.11 and 3.6.14. (CVE-2022-0391)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0102");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26116");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26137");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3177");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0391");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'python-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-debug-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-debuginfo-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-devel-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-libs-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-test-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'python-tools-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite',
    'tkinter-2.7.5-92.el7_9.cgslv5.0.2.g8de3186.lite'
  ],
  'CGSL MAIN 5.04': [
    'python-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-debug-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-debuginfo-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-devel-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-libs-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-test-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'python-tools-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4',
    'tkinter-2.7.5-92.el7_9.cgslv5.0.2.gc640cb4'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python');
}
