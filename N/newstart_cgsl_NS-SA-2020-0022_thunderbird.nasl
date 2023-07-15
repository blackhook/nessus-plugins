#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0022. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134410);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-11703",
    "CVE-2019-11704",
    "CVE-2019-11705",
    "CVE-2019-11706",
    "CVE-2019-11707",
    "CVE-2019-11708",
    "CVE-2019-11709",
    "CVE-2019-11711",
    "CVE-2019-11712",
    "CVE-2019-11713",
    "CVE-2019-11715",
    "CVE-2019-11717",
    "CVE-2019-11730",
    "CVE-2019-11739",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11752",
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
  script_bugtraq_id(
    108761,
    108810,
    108835,
    109086
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2019-0458");

  script_name(english:"NewStart CGSL MAIN 4.05 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - Insufficient vetting of parameters passed with the
    Prompt:Open IPC message between child and parent
    processes can result in the non-sandboxed parent process
    opening web content chosen by a compromised child
    process. When combined with additional vulnerabilities
    this could result in executing arbitrary code on the
    user's computer. This vulnerability affects Firefox ESR
    < 60.7.2, Firefox < 67.0.4, and Thunderbird < 60.7.2.
    (CVE-2019-11708)

  - A type confusion vulnerability can occur when
    manipulating JavaScript objects due to issues in
    Array.pop. This can allow for an exploitable crash. We
    are aware of targeted attacks in the wild abusing this
    flaw. This vulnerability affects Firefox ESR < 60.7.1,
    Firefox < 67.0.3, and Thunderbird < 60.7.2.
    (CVE-2019-11707)

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

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in icalmemory_strdup_and_dequote
    when processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11704)

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in parser_get_next_char when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11703)

  - Encrypted S/MIME parts in a crafted
    multipart/alternative message can leak plaintext when
    included in a a HTML reply/forward. This vulnerability
    affects Thunderbird < 68.1 and Thunderbird < 60.9.
    (CVE-2019-11739)

  - In libexpat before 2.2.8, crafted XML input could fool
    the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to
    XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read.
    (CVE-2019-15903)

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

  - A flaw in Thunderbird's implementation of iCal causes a
    stack buffer overflow in icalrecur_add_bydayrules when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11705)

  - A flaw in Thunderbird's implementation of iCal causes a
    type confusion in icaltimezone_get_vtimezone_properties
    when processing certain email messages, resulting in a
    crash. This vulnerability affects Thunderbird < 60.7.1.
    (CVE-2019-11706)

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
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0022");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "thunderbird-68.4.1-2.el6.centos",
    "thunderbird-debuginfo-68.4.1-2.el6.centos"
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
