#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0147. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154450);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2019-16935",
    "CVE-2019-20907",
    "CVE-2020-8492",
    "CVE-2020-14422"
  );
  script_xref(name:"IAVA", value:"2020-A-0340-S");
  script_xref(name:"IAVA", value:"2020-A-0103-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : python3 Multiple Vulnerabilities (NS-SA-2021-0147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has python3 packages installed that are affected
by multiple vulnerabilities:

  - The documentation XML-RPC server in Python through 2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with untrusted input, arbitrary
    JavaScript can be delivered to clients that visit the http URL for this server. (CVE-2019-16935)

  - In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an
    infinite loop when opened by tarfile.open, because _proc_pax lacks header validation. (CVE-2019-20907)

  - Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and
    IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application
    is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this
    attacker can cause many dictionary entries to be created. This is fixed in: v3.5.10, v3.5.10rc1; v3.6.12;
    v3.7.9; v3.8.4, v3.8.4rc1, v3.8.5, v3.8.6, v3.8.6rc1; v3.9.0, v3.9.0b4, v3.9.0b5, v3.9.0rc1, v3.9.0rc2.
    (CVE-2020-14422)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0147");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-16935");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-20907");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14422");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8492");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python3 packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'python3-3.6.8-18.el7',
    'python3-debug-3.6.8-18.el7',
    'python3-devel-3.6.8-18.el7',
    'python3-idle-3.6.8-18.el7',
    'python3-libs-3.6.8-18.el7',
    'python3-test-3.6.8-18.el7',
    'python3-tkinter-3.6.8-18.el7'
  ],
  'CGSL MAIN 5.05': [
    'python3-3.6.8-18.el7',
    'python3-debug-3.6.8-18.el7',
    'python3-devel-3.6.8-18.el7',
    'python3-idle-3.6.8-18.el7',
    'python3-libs-3.6.8-18.el7',
    'python3-test-3.6.8-18.el7',
    'python3-tkinter-3.6.8-18.el7'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3');
}
