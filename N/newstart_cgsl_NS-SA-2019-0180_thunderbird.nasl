#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0180. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129901);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-11709",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11715",
    "CVE-2019-11717",
    "CVE-2019-11730"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 67 and Firefox ESR 60.7.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort that some of
    these could be exploited to run arbitrary code. This
    vulnerability affects Firefox ESR < 60.8, Firefox < 68,
    and Thunderbird < 60.8. (CVE-2019-11709)

  - When an inner window is reused, it does not consider the
    use of document.domain for cross-origin protections. If
    pages on different subdomains ever cooperatively use
    document.domain, then either page can abuse this to
    inject script into arbitrary pages on the other
    subdomain, even those that did not use document.domain
    to relax their origin security. This vulnerability
    affects Firefox ESR < 60.8, Firefox < 68, and
    Thunderbird < 60.8. (CVE-2019-11711)

  - POST requests made by NPAPI plugins, such as Flash, that
    receive a status 308 redirect response can bypass CORS
    requirements. This can allow an attacker to perform
    Cross-Site Request Forgery (CSRF) attacks. This
    vulnerability affects Firefox ESR < 60.8, Firefox < 68,
    and Thunderbird < 60.8. (CVE-2019-11712)

  - A use-after-free vulnerability can occur in HTTP/2 when
    a cached HTTP/2 stream is closed while still in use,
    resulting in a potentially exploitable crash. This
    vulnerability affects Firefox ESR < 60.8, Firefox < 68,
    and Thunderbird < 60.8. (CVE-2019-11713)

  - Due to an error while parsing page content, it is
    possible for properly sanitized user input to be
    misinterpreted and lead to XSS hazards on web sites in
    certain circumstances. This vulnerability affects
    Firefox ESR < 60.8, Firefox < 68, and Thunderbird <
    60.8. (CVE-2019-11715)

  - A vulnerability exists where the caret (^) character
    is improperly escaped constructing some URIs due to it
    being used as a separator, allowing for possible
    spoofing of origin attributes. This vulnerability
    affects Firefox ESR < 60.8, Firefox < 68, and
    Thunderbird < 60.8. (CVE-2019-11717)

  - A vulnerability exists where if a user opens a locally
    saved HTML file, this file can use file: URIs to access
    other files in the same directory or sub-directories if
    the names are known or guessed. The Fetch API can then
    be used to read the contents of any files stored in
    these directories and they may uploaded to a server. It
    was demonstrated that in combination with a popular
    Android messaging app, if a malicious HTML attachment is
    sent to a user and they opened that attachment in
    Firefox, due to that app's predictable pattern for
    locally-saved file names, it is possible to read
    attachments the victim received from other
    correspondents. This vulnerability affects Firefox ESR <
    60.8, Firefox < 68, and Thunderbird < 60.8.
    (CVE-2019-11730)

  - As part of a winning Pwn2Own entry, a researcher
    demonstrated a sandbox escape by installing a malicious
    language pack and then opening a browser feature that
    used the compromised translation. This vulnerability
    affects Firefox ESR < 60.8, Firefox < 68, and
    Thunderbird < 60.8. (CVE-2019-9811)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0180");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

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
    "thunderbird-60.8.0-1.el7.centos",
    "thunderbird-debuginfo-60.8.0-1.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "thunderbird-60.8.0-1.el7.centos",
    "thunderbird-debuginfo-60.8.0-1.el7.centos"
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
