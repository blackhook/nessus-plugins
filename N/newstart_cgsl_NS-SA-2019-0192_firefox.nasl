#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0192. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129926);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-9812",
    "CVE-2019-11733",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11752"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : firefox Multiple Vulnerabilities (NS-SA-2019-0192)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has firefox packages installed that are affected
by multiple vulnerabilities:

  - When a master password is set, it is required to be
    entered again before stored passwords can be accessed in
    the 'Saved Logins' dialog. It was found that locally
    stored passwords can be copied to the clipboard thorough
    the 'copy password' context menu item without re-
    entering the master password if the master password had
    been previously entered in the same session, allowing
    for potential theft of stored passwords. This
    vulnerability affects Firefox < 68.0.2 and Firefox ESR <
    68.0.2. (CVE-2019-11733)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 68, Firefox ESR 68, and
    Firefox 60.8. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR <
    60.9, and Firefox ESR < 68.1. (CVE-2019-11740)

  - A same-origin policy violation occurs allowing the theft
    of cross-origin images through a combination of SVG
    filters and a <canvas> element due to an error in
    how same-origin policy is applied to cached image
    content. The resulting same-origin policy violation
    could allow for data theft. This vulnerability affects
    Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9,
    Firefox ESR < 60.9, and Firefox ESR < 68.1.
    (CVE-2019-11742)

  - Navigation events were not fully adhering to the W3C's
    Navigation-Timing Level 2 draft specification in some
    instances for the unload event, which restricts access
    to detailed timing attributes to only be same-origin.
    This resulted in potential cross-origin information
    exposure of history through timing side-channel attacks.
    This vulnerability affects Firefox < 69, Thunderbird <
    68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
    Firefox ESR < 68.1. (CVE-2019-11743)

  - Some HTML elements, such as <title> and
    <textarea>, can contain literal angle brackets
    without treating them as markup. It is possible to pass
    a literal closing tag to .innerHTML on these elements,
    and subsequent content after that will be parsed as if
    it were outside the tag. This can lead to XSS if a site
    does not filter user input as strictly for these
    elements as it does for other elements. This
    vulnerability affects Firefox < 69, Thunderbird < 68.1,
    Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR
    < 68.1. (CVE-2019-11744)

  - A use-after-free vulnerability can occur while
    manipulating video elements if the body is freed while
    still in use. This results in a potentially exploitable
    crash. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR <
    60.9, and Firefox ESR < 68.1. (CVE-2019-11746)

  - It is possible to delete an IndexedDB key value and
    subsequently try to extract it during conversion. This
    results in a use-after-free and a potentially
    exploitable crash. This vulnerability affects Firefox <
    69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR
    < 60.9, and Firefox ESR < 68.1. (CVE-2019-11752)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0192");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "firefox-60.9.0-1.el7.centos",
    "firefox-debuginfo-60.9.0-1.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "firefox-60.9.0-1.el7.centos",
    "firefox-debuginfo-60.9.0-1.el7.centos"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
