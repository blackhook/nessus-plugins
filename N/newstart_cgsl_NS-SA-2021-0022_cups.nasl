##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0022. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147300);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2017-18190", "CVE-2019-8675", "CVE-2019-8696");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : cups Multiple Vulnerabilities (NS-SA-2021-0022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has cups packages installed that are affected by
multiple vulnerabilities:

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Mojave
    10.14.6, Security Update 2019-004 High Sierra, Security Update 2019-004 Sierra. An attacker in a
    privileged network position may be able to execute arbitrary code. (CVE-2019-8675, CVE-2019-8696)

  - A localhost.localdomain whitelist entry in valid_host() in scheduler/client.c in CUPS before 2.2.2 allows
    remote attackers to execute arbitrary IPP commands by sending POST requests to the CUPS daemon in
    conjunction with DNS rebinding. The localhost.localdomain name is often resolved via a DNS server (neither
    the OS nor the web browser is responsible for ensuring that localhost.localdomain is 127.0.0.1).
    (CVE-2017-18190)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0022");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL cups packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
    'cups-1.6.3-51.el7',
    'cups-client-1.6.3-51.el7',
    'cups-debuginfo-1.6.3-51.el7',
    'cups-devel-1.6.3-51.el7',
    'cups-filesystem-1.6.3-51.el7',
    'cups-ipptool-1.6.3-51.el7',
    'cups-libs-1.6.3-51.el7',
    'cups-lpd-1.6.3-51.el7'
  ],
  'CGSL MAIN 5.04': [
    'cups-1.6.3-51.el7',
    'cups-client-1.6.3-51.el7',
    'cups-debuginfo-1.6.3-51.el7',
    'cups-devel-1.6.3-51.el7',
    'cups-filesystem-1.6.3-51.el7',
    'cups-ipptool-1.6.3-51.el7',
    'cups-libs-1.6.3-51.el7',
    'cups-lpd-1.6.3-51.el7'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups');
}
