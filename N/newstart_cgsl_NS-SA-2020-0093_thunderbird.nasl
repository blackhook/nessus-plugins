##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0093. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143979);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17022",
    "CVE-2019-17024",
    "CVE-2019-17026",
    "CVE-2019-20503",
    "CVE-2020-6792",
    "CVE-2020-6793",
    "CVE-2020-6794",
    "CVE-2020-6795",
    "CVE-2020-6798",
    "CVE-2020-6800",
    "CVE-2020-6805",
    "CVE-2020-6806",
    "CVE-2020-6807",
    "CVE-2020-6811",
    "CVE-2020-6812",
    "CVE-2020-6814",
    "CVE-2020-6819",
    "CVE-2020-6820",
    "CVE-2020-6821",
    "CVE-2020-6822",
    "CVE-2020-6825",
    "CVE-2020-6831",
    "CVE-2020-12387",
    "CVE-2020-12392",
    "CVE-2020-12395",
    "CVE-2020-12397"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0032");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0093)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - When removing data about an origin whose tab was recently closed, a use-after-free could occur in the
    Quota manager, resulting in a potentially exploitable crash. This vulnerability affects Thunderbird <
    68.6, Firefox < 74, Firefox < ESR68.6, and Firefox ESR < 68.6. (CVE-2020-6805)

  - By carefully crafting promise resolutions, it was possible to cause an out-of-bounds read off the end of
    an array resized during script execution. This could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox < ESR68.6, and
    Firefox ESR < 68.6. (CVE-2020-6806)

  - When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer does not
    escape < and > characters. Because the resulting string is pasted directly into the text node of the
    element this does not result in a direct injection into the webpage; however, if a webpage subsequently
    copies the node's innerHTML, assigning it to another innerHTML, this would result in an XSS vulnerability.
    Two WYSIWYG editors were identified with this behavior, more may exist. This vulnerability affects Firefox
    ESR < 68.4 and Firefox < 72. (CVE-2019-17022)

  - When pasting a <style> tag from the clipboard into a rich text editor, the CSS sanitizer incorrectly
    rewrites a @namespace rule. This could allow for injection into certain types of websites resulting in
    data exfiltration. This vulnerability affects Firefox ESR < 68.4 and Firefox < 72. (CVE-2019-17016)

  - Due to a missing case handling object types, a type confusion vulnerability could occur, resulting in a
    crash. We presume that with enough effort that it could be exploited to run arbitrary code. This
    vulnerability affects Firefox ESR < 68.4 and Firefox < 72. (CVE-2019-17017)

  - Mozilla developers reported memory safety bugs present in Firefox 71 and Firefox ESR 68.3. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 68.4 and Firefox < 72.
    (CVE-2019-17024)

  - Incorrect alias information in IonMonkey JIT compiler for setting array elements could lead to a type
    confusion. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects
    Firefox ESR < 68.4.1, Thunderbird < 68.4.1, and Firefox < 72.0.1. (CVE-2019-17026)

  - When processing an email message with an ill-formed envelope, Thunderbird could read data from a random
    memory location. This vulnerability affects Thunderbird < 68.5. (CVE-2020-6793)

  - When processing a message that contains multiple S/MIME signatures, a bug in the MIME processing code
    caused a null pointer dereference, leading to an unexploitable crash. This vulnerability affects
    Thunderbird < 68.5. (CVE-2020-6795)

  - When deriving an identifier for an email message, uninitialized memory was used in addition to the message
    contents. This vulnerability affects Thunderbird < 68.5. (CVE-2020-6792)

  - If a template tag was used in a select tag, the parser could be confused and allow JavaScript parsing and
    execution when it should not be allowed. A site that relied on the browser behaving correctly could suffer
    a cross-site scripting vulnerability as a result. In general, this flaw cannot be exploited through email
    in the Thunderbird product because scripting is disabled when reading mail, but is potentially a risk in
    browser or browser-like contexts. This vulnerability affects Thunderbird < 68.5, Firefox < 73, and Firefox
    < ESR68.5. (CVE-2020-6798)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 72 and Firefox ESR
    68.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. In general, these flaws cannot be exploited
    through email in the Thunderbird product because scripting is disabled when reading mail, but are
    potentially risks in browser or browser-like contexts. This vulnerability affects Thunderbird < 68.5,
    Firefox < 73, and Firefox < ESR68.5. (CVE-2020-6800)

  - If a user saved passwords before Thunderbird 60 and then later set a master password, an unencrypted copy
    of these passwords is still accessible. This is because the older stored password file was not deleted
    when the data was copied to a new format starting in Thunderbird 60. The new master password is added only
    on the new file. This could allow the exposure of stored password data outside of user expectations. This
    vulnerability affects Thunderbird < 68.5. (CVE-2020-6794)

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

  - Under certain conditions, when running the nsDocShell destructor, a race condition can cause a use-after-
    free. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects
    Thunderbird < 68.7.0, Firefox < 74.0.1, and Firefox ESR < 68.6.1. (CVE-2020-6819)

  - Under certain conditions, when handling a ReadableStream, a race condition can cause a use-after-free. We
    are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects Thunderbird <
    68.7.0, Firefox < 74.0.1, and Firefox ESR < 68.6.1. (CVE-2020-6820)

  - When reading from areas partially or fully outside the source resource with WebGL's
    copyTexSubImage method, the specification requires the returned values be zero. Previously,
    this memory was uninitialized, leading to potentially sensitive data disclosure. This vulnerability
    affects Thunderbird < 68.7.0, Firefox ESR < 68.7, and Firefox < 75. (CVE-2020-6821)

  - On 32-bit builds, an out of bounds write could have occurred when processing an image larger than 4 GB in
    GMPDecodeData. It is possible that with enough effort this could have been exploited to run
    arbitrary code. This vulnerability affects Thunderbird < 68.7.0, Firefox ESR < 68.7, and Firefox < 75.
    (CVE-2020-6822)

  - Mozilla developers and community members Tyson Smith and Christian Holler reported memory safety bugs
    present in Firefox 74 and Firefox ESR 68.6. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 68.7.0, Firefox ESR < 68.7, and Firefox < 75. (CVE-2020-6825)

  - A race condition when running shutdown code for Web Worker led to a use-after-free vulnerability. This
    resulted in a potentially exploitable crash. This vulnerability affects Firefox ESR < 68.8, Firefox < 76,
    and Thunderbird < 68.8.0. (CVE-2020-12387)

  - A buffer overflow could occur when parsing and validating SCTP chunks in WebRTC. This could have led to
    memory corruption and a potentially exploitable crash. This vulnerability affects Firefox ESR < 68.8,
    Firefox < 76, and Thunderbird < 68.8.0. (CVE-2020-6831)

  - The 'Copy as cURL' feature of Devtools' network tab did not properly escape the HTTP POST data of a
    request, which can be controlled by the website. If a user used the 'Copy as cURL' feature and pasted the
    command into a terminal, it could have resulted in the disclosure of local files. This vulnerability
    affects Firefox ESR < 68.8, Firefox < 76, and Thunderbird < 68.8.0. (CVE-2020-12392)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 75 and Firefox ESR
    68.7. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 68.8,
    Firefox < 76, and Thunderbird < 68.8.0. (CVE-2020-12395)

  - By encoding Unicode whitespace characters within the From email header, an attacker can spoof the sender
    email address that Thunderbird displays. This vulnerability affects Thunderbird < 68.8.0. (CVE-2020-12397)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0093");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.05': [
    'thunderbird-68.8.0-1.el7.centos',
    'thunderbird-debuginfo-68.8.0-1.el7.centos'
  ],
  'CGSL MAIN 5.05': [
    'thunderbird-68.8.0-1.el7.centos',
    'thunderbird-debuginfo-68.8.0-1.el7.centos'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
