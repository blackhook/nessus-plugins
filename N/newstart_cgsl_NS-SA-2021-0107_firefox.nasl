#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0107. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154623);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id(
    "CVE-2021-23961",
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24002",
    "CVE-2021-29945",
    "CVE-2021-29946"
  );
  script_xref(name:"IAVA", value:"2021-A-0051-S");
  script_xref(name:"IAVA", value:"2021-A-0185-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : firefox Multiple Vulnerabilities (NS-SA-2021-0107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has firefox packages installed that are affected
by multiple vulnerabilities:

  - Further techniques that built on the slipstream research combined with a malicious webpage could have
    exposed both an internal network's hosts as well as services running on the user's local machine. This
    vulnerability affects Firefox < 85. (CVE-2021-23961)

  - A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound
    write. This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88.
    (CVE-2021-23994)

  - When Responsive Design Mode was enabled, it used references to objects that were previously freed. We
    presume that with enough effort this could have been exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-23995)

  - Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon
    from an HTTPS page. This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88.
    (CVE-2021-23998)

  - If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System
    Principal and granted additional privileges that should not be granted to web content. This vulnerability
    affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-23999)

  - When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would
    have been interpreted as such and allowed arbitrary commands to be sent to the FTP server. This
    vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-24002)

  - The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and
    result in a crash. *Note: This issue only affected x86-32 platforms. Other platforms are unaffected.*.
    This vulnerability affects Firefox ESR < 78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-29945)

  - Ports that were written as an integer overflow above the bounds of a 16-bit integer could have bypassed
    port blocking restrictions when used in the Alt-Svc header. This vulnerability affects Firefox ESR <
    78.10, Thunderbird < 78.10, and Firefox < 88. (CVE-2021-29946)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0107");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23961");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23994");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23995");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23998");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-23999");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-24002");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29945");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29946");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox-debuginfo");
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
    'firefox-78.10.0-1.el7.centos',
    'firefox-debuginfo-78.10.0-1.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'firefox-78.10.0-1.el7.centos',
    'firefox-debuginfo-78.10.0-1.el7.centos'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
