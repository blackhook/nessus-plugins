#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0003. The text
# itself is copyright (C) ZTE, Inc.


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133071);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-11757",
    "CVE-2019-11758",
    "CVE-2019-11759",
    "CVE-2019-11760",
    "CVE-2019-11761",
    "CVE-2019-11762",
    "CVE-2019-11763",
    "CVE-2019-11764",
    "CVE-2019-15903",
    "CVE-2019-17005",
    "CVE-2019-17008",
    "CVE-2019-17010",
    "CVE-2019-17011",
    "CVE-2019-17012"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - In libexpat before 2.2.8, crafted XML input could fool
    the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to
    XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read.
    (CVE-2019-15903)

  - When following the value's prototype chain, it was
    possible to retain a reference to a locale, delete it,
    and subsequently reference it. This resulted in a use-
    after-free and a potentially exploitable crash. This
    vulnerability affects Firefox < 70, Thunderbird < 68.2,
    and Firefox ESR < 68.2. (CVE-2019-11757)

  - Mozilla community member Philipp reported a memory
    safety bug present in Firefox 68 when 360 Total Security
    was installed. This bug showed evidence of memory
    corruption in the accessibility engine and we presume
    that with enough effort that it could be exploited to
    run arbitrary code. This vulnerability affects Firefox <
    69, Thunderbird < 68.2, and Firefox ESR < 68.2.
    (CVE-2019-11758)

  - If two same-origin documents set document.domain
    differently to become cross-origin, it was possible for
    them to call arbitrary DOM methods/getters/setters on
    the now-cross-origin window. This vulnerability affects
    Firefox < 70, Thunderbird < 68.2, and Firefox ESR <
    68.2. (CVE-2019-11762)

  - Failure to correctly handle null bytes when processing
    HTML entities resulted in Firefox incorrectly parsing
    these entities. This could have led to HTML comment text
    being treated as HTML which could have led to XSS in a
    web application under certain conditions. It could have
    also led to HTML entities being masked from filters -
    enabling the use of entities to mask the actual
    characters of interest from filters. This vulnerability
    affects Firefox < 70, Thunderbird < 68.2, and Firefox
    ESR < 68.2. (CVE-2019-11763)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 69 and Firefox ESR 68.1.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these
    could be exploited to run arbitrary code. This
    vulnerability affects Firefox < 70, Thunderbird < 68.2,
    and Firefox ESR < 68.2. (CVE-2019-11764)

  - An attacker could have caused 4 bytes of HMAC output to
    be written past the end of a buffer stored on the stack.
    This could be used by an attacker to execute arbitrary
    code or more likely lead to a crash. This vulnerability
    affects Firefox < 70, Thunderbird < 68.2, and Firefox
    ESR < 68.2. (CVE-2019-11759)

  - A fixed-size stack buffer could overflow in nrappkit
    when doing WebRTC signaling. This resulted in a
    potentially exploitable crash in some instances. This
    vulnerability affects Firefox < 70, Thunderbird < 68.2,
    and Firefox ESR < 68.2. (CVE-2019-11760)

  - By using a form with a data URI it was possible to gain
    access to the privileged JSONView object that had been
    cloned into content. Impact from exposing this object
    appears to be minimal, however it was a bypass of
    existing defense in depth mechanisms. This vulnerability
    affects Firefox < 70, Thunderbird < 68.2, and Firefox
    ESR < 68.2. (CVE-2019-11761)

  - Under certain conditions, when checking the Resist
    Fingerprinting preference during device orientation
    checks, a race condition could have caused a use-after-
    free and a potentially exploitable crash. This
    vulnerability affects Thunderbird < 68.3, Firefox ESR <
    68.3, and Firefox < 71. (CVE-2019-17010)

  - Under certain conditions, when retrieving a document
    from a DocShell in the antitracking code, a race
    condition could cause a use-after-free condition and a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-17011)

  - Mozilla developers reported memory safety bugs present
    in Firefox 70 and Firefox ESR 68.2. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability
    affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-17012)

  - When using nested workers, a use-after-free could occur
    during worker destruction. This resulted in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-17008)

  - The plain text serializer used a fixed-size array for
    the number of  elements it could process; however it
    was possible to overflow the static-sized array leading
    to memory corruption and a potentially exploitable
    crash. This vulnerability affects Thunderbird < 68.3,
    Firefox ESR < 68.3, and Firefox < 71. (CVE-2019-17005)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0003");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "thunderbird-68.3.0-1.el7.centos",
    "thunderbird-debuginfo-68.3.0-1.el7.centos"
  ],
  "CGSL MAIN 5.05": [
    "thunderbird-68.3.0-1.el7.centos",
    "thunderbird-debuginfo-68.3.0-1.el7.centos"
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
