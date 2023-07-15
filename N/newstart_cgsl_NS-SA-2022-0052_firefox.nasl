##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0052. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160768);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-29967",
    "CVE-2021-29970",
    "CVE-2021-29976",
    "CVE-2021-29980",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-30547"
  );
  script_xref(name:"IAVA", value:"2021-A-0264-S");
  script_xref(name:"IAVA", value:"2021-A-0309-S");
  script_xref(name:"IAVA", value:"2021-A-0366-S");
  script_xref(name:"IAVA", value:"2021-A-0293-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : firefox Multiple Vulnerabilities (NS-SA-2022-0052)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has firefox packages installed that are affected by multiple
vulnerabilities:

  - Mozilla developers reported memory safety bugs present in Firefox 88 and Firefox ESR 78.11. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.11, Firefox < 89, and
    Firefox ESR < 78.11. (CVE-2021-29967)

  - A malicious webpage could have triggered a use-after-free, memory corruption, and a potentially
    exploitable crash. *This bug could only be triggered when accessibility was enabled.*. This vulnerability
    affects Thunderbird < 78.12, Firefox ESR < 78.12, and Firefox < 90. (CVE-2021-29970)

  - Mozilla developers reported memory safety bugs present in code shared between Firefox and Thunderbird.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.12,
    Firefox ESR < 78.12, and Firefox < 90. (CVE-2021-29976)

  - Uninitialized memory in a canvas object could have caused an incorrect free() leading to memory corruption
    and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91,
    Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29980)

  - Instruction reordering resulted in a sequence of instructions that would cause an object to be incorrectly
    considered during garbage collection. This led to memory corruption and a potentially exploitable crash.
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29984)

  - A use-after-free vulnerability in media channels could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29985)

  - A suspected race condition when calling getaddrinfo led to memory corruption and a potentially exploitable
    crash. *Note: This issue only affected Linux operating systems. Other operating systems are unaffected.*
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29986)

  - Firefox incorrectly treated an inline list-item element as a block element, resulting in an out of bounds
    read or memory corruption, and a potentially exploitable crash. This vulnerability affects Thunderbird <
    78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29988)

  - Mozilla developers reported memory safety bugs present in Firefox 90 and Firefox ESR 78.12. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.13, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29989)

  - Out of bounds write in ANGLE in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2021-30547)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0052");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29967");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29970");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29976");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29980");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29984");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29985");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29986");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29988");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29989");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-30547");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
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
    'firefox-78.13.0-2.el8_4'
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
