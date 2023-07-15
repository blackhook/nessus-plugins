#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0101. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154515);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2021-23981",
    "CVE-2021-23982",
    "CVE-2021-23984",
    "CVE-2021-23987"
  );
  script_xref(name:"IAVA", value:"2021-A-0144-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2021-0101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - A texture upload of a Pixel Buffer Object could have confused the WebGL code to skip binding the buffer
    used to unpack it, resulting in memory corruption and a potentially exploitable information leak or crash.
    This vulnerability affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23981)

  - Using techniques that built on the slipstream research, a malicious webpage could have scanned both an
    internal network's hosts as well as services running on the user's local machine utilizing WebRTC
    connections. This vulnerability affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9.
    (CVE-2021-23982)

  - A malicious extension could have opened a popup window lacking an address bar. The title of the popup
    lacking an address bar should not be fully controllable, but in this situation was. This could have been
    used to spoof a website and attempt to trick the user into providing credentials. This vulnerability
    affects Firefox ESR < 78.9, Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23984)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 86 and Firefox ESR
    78.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.9,
    Firefox < 87, and Thunderbird < 78.9. (CVE-2021-23987)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0101");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23981");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23982");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23984");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23987");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23987");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:thunderbird");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'thunderbird-78.9.0-3.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'thunderbird-78.9.0-3.el7.centos'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
