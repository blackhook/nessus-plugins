#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0093. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(127315);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2016-5824",
    "CVE-2018-12405",
    "CVE-2018-17466",
    "CVE-2018-18492",
    "CVE-2018-18493",
    "CVE-2018-18494",
    "CVE-2018-18498",
    "CVE-2018-18500",
    "CVE-2018-18501",
    "CVE-2018-18505"
  );

  script_name(english:"NewStart CGSL MAIN 4.06 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0093)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - libical 1.0 allows remote attackers to cause a denial of
    service (use-after-free) via a crafted ics file.
    (CVE-2016-5824)

  - A use-after-free vulnerability can occur while parsing
    an HTML5 stream in concert with custom HTML elements.
    This results in the stream parser object being freed
    while still in use, leading to a potentially exploitable
    crash. This vulnerability affects Thunderbird < 60.5,
    Firefox ESR < 60.5, and Firefox < 65. (CVE-2018-18500)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 64 and Firefox ESR 60.4.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort that some of
    these could be exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 60.5, Firefox ESR <
    60.5, and Firefox < 65. (CVE-2018-18501)

  - An earlier fix for an Inter-process Communication (IPC)
    vulnerability, CVE-2011-3079, added authentication to
    communication between IPC endpoints and server parents
    during IPC process creation. This authentication is
    insufficient for channels created after the IPC process
    is started, leading to the authentication not being
    correctly applied to later channels. This could allow
    for a sandbox escape through IPC channels due to lack of
    message validation in the listener process. This
    vulnerability affects Thunderbird < 60.5, Firefox ESR <
    60.5, and Firefox < 65. (CVE-2018-18505)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 63 and Firefox ESR 60.3.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort that some of
    these could be exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 60.4, Firefox ESR <
    60.4, and Firefox < 64. (CVE-2018-12405)

  - A use-after-free vulnerability can occur after deleting
    a selection element due to a weak reference to the
    select element in the options collection. This results
    in a potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.4, Firefox ESR < 60.4, and
    Firefox < 64. (CVE-2018-18492)

  - A buffer overflow can occur in the Skia library during
    buffer offset calculations with hardware accelerated
    canvas 2D actions due to the use of 32-bit calculations
    instead of 64-bit. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 60.4, Firefox ESR < 60.4, and Firefox <
    64. (CVE-2018-18493)

  - A same-origin policy violation allowing the theft of
    cross-origin URL entries when using the Javascript
    location property to cause a redirection to another site
    using performance.getEntries(). This is a same-origin
    policy violation and could allow for data theft. This
    vulnerability affects Thunderbird < 60.4, Firefox ESR <
    60.4, and Firefox < 64. (CVE-2018-18494)

  - A potential vulnerability leading to an integer overflow
    can occur during buffer size calculations for images
    when a raw value is used instead of the checked value.
    This leads to a possible out-of-bounds write. This
    vulnerability affects Thunderbird < 60.4, Firefox ESR <
    60.4, and Firefox < 64. (CVE-2018-18498)

  - Incorrect texture handling in Angle in Google Chrome
    prior to 70.0.3538.67 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML
    page. (CVE-2018-17466)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0093");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18505");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "thunderbird-60.6.1-1.el6.centos",
    "thunderbird-debuginfo-60.6.1-1.el6.centos"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
