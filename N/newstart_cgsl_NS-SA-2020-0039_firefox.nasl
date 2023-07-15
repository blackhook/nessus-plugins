#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0039. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140292);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-20503",
    "CVE-2020-6805",
    "CVE-2020-6806",
    "CVE-2020-6807",
    "CVE-2020-6811",
    "CVE-2020-6812",
    "CVE-2020-6814"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : firefox Multiple Vulnerabilities (NS-SA-2020-0039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has firefox packages installed that are affected
by multiple vulnerabilities:

  - When removing data about an origin whose tab was recently closed, a use-after-free could occur in the
    Quota manager, resulting in a potentially exploitable crash. This vulnerability affects Thunderbird <
    68.6, Firefox < 74, Firefox < ESR68.6, and Firefox ESR < 68.6. (CVE-2020-6805)

  - By carefully crafting promise resolutions, it was possible to cause an out-of-bounds read off the end of
    an array resized during script execution. This could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox < ESR68.6, and
    Firefox ESR < 68.6. (CVE-2020-6806)

  - The 'Copy as cURL' feature of Devtools' network tab did not properly escape the HTTP method of a request,
    which can be controlled by the website. If a user used the 'Copy as Curl' feature and pasted the command
    into a terminal, it could have resulted in command injection and arbitrary command execution. This
    vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox < ESR68.6, and Firefox ESR < 68.6.
    (CVE-2020-6811)

  - usrsctp before 2019-12-20 has out-of-bounds reads in sctp_load_addresses_from_init. (CVE-2019-20503)

  - The first time AirPods are connected to an iPhone, they become named after the user's name by default
    (e.g. Jane Doe's AirPods.) Websites with camera or microphone permission are able to enumerate device
    names, disclosing the user's name. To resolve this issue, Firefox added a special case that renames
    devices containing the substring 'AirPods' to simply 'AirPods'. This vulnerability affects Thunderbird <
    68.6, Firefox < 74, Firefox < ESR68.6, and Firefox ESR < 68.6. (CVE-2020-6812)

  - When a device was changed while a stream was about to be destroyed, the stream-reinit task
    may have been executed after the stream was destroyed, causing a use-after-free and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox < ESR68.6, and
    Firefox ESR < 68.6. (CVE-2020-6807)

  - Mozilla developers reported memory safety bugs present in Firefox and Thunderbird 68.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox <
    ESR68.6, and Firefox ESR < 68.6. (CVE-2020-6814)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0039");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6814");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'firefox-68.6.0-1.el7.centos',
    'firefox-debuginfo-68.6.0-1.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'firefox-68.6.0-1.el7.centos',
    'firefox-debuginfo-68.6.0-1.el7.centos'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}


