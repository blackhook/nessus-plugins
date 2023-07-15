#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0010. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134321);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17022",
    "CVE-2019-17024",
    "CVE-2019-17026"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - When pasting a <style> tag from the clipboard into
    a rich text editor, the CSS sanitizer does not escape
    < and > characters. Because the resulting string
    is pasted directly into the text node of the element
    this does not result in a direct injection into the
    webpage; however, if a webpage subsequently copies the
    node's innerHTML, assigning it to another innerHTML,
    this would result in an XSS vulnerability. Two WYSIWYG
    editors were identified with this behavior, more may
    exist. This vulnerability affects Firefox ESR < 68.4 and
    Firefox < 72. (CVE-2019-17022)

  - When pasting a <style> tag from the clipboard into
    a rich text editor, the CSS sanitizer incorrectly
    rewrites a @namespace rule. This could allow for
    injection into certain types of websites resulting in
    data exfiltration. This vulnerability affects Firefox
    ESR < 68.4 and Firefox < 72. (CVE-2019-17016)

  - Due to a missing case handling object types, a type
    confusion vulnerability could occur, resulting in a
    crash. We presume that with enough effort that it could
    be exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 68.4 and Firefox < 72.
    (CVE-2019-17017)

  - Mozilla developers reported memory safety bugs present
    in Firefox 71 and Firefox ESR 68.3. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 68.4 and Firefox < 72.
    (CVE-2019-17024)

  - Incorrect alias information in IonMonkey JIT compiler
    for setting array elements could lead to a type
    confusion. We are aware of targeted attacks in the wild
    abusing this flaw. This vulnerability affects Firefox
    ESR < 68.4.1, Thunderbird < 68.4.1, and Firefox <
    72.0.1. (CVE-2019-17026)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0010");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17026");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "thunderbird-68.4.1-2.el7.centos",
    "thunderbird-debuginfo-68.4.1-2.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "thunderbird-68.4.1-2.el7.centos",
    "thunderbird-debuginfo-68.4.1-2.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
