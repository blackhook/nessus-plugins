#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0004. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147407);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-9812",
    "CVE-2019-11733",
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
    "CVE-2019-17005",
    "CVE-2019-17008",
    "CVE-2019-17010",
    "CVE-2019-17011",
    "CVE-2019-17012",
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17022",
    "CVE-2019-17024",
    "CVE-2019-17026",
    "CVE-2019-20503",
    "CVE-2020-6463",
    "CVE-2020-6514",
    "CVE-2020-6796",
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
    "CVE-2020-12405",
    "CVE-2020-12406",
    "CVE-2020-12410",
    "CVE-2020-12418",
    "CVE-2020-12419",
    "CVE-2020-12420",
    "CVE-2020-12421",
    "CVE-2020-15652",
    "CVE-2020-15659",
    "CVE-2020-15664",
    "CVE-2020-15669",
    "CVE-2020-15673",
    "CVE-2020-15676",
    "CVE-2020-15677",
    "CVE-2020-15678",
    "CVE-2020-15683",
    "CVE-2020-15969",
    "CVE-2020-26950"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0032");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"NewStart CGSL MAIN 4.06 : firefox Multiple Vulnerabilities (NS-SA-2021-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has firefox packages installed that are affected by multiple
vulnerabilities:

  - When removing data about an origin whose tab was recently closed, a use-after-free could occur in the
    Quota manager, resulting in a potentially exploitable crash. This vulnerability affects Thunderbird <
    68.6, Firefox < 74, Firefox < ESR68.6, and Firefox ESR < 68.6. (CVE-2020-6805)

  - When a master password is set, it is required to be entered again before stored passwords can be accessed
    in the 'Saved Logins' dialog. It was found that locally stored passwords can be copied to the clipboard
    thorough the 'copy password' context menu item without re-entering the master password if the master
    password had been previously entered in the same session, allowing for potential theft of stored
    passwords. This vulnerability affects Firefox < 68.0.2 and Firefox ESR < 68.0.2. (CVE-2019-11733)

  - Given a compromised sandboxed content process due to a separate vulnerability, it is possible to escape
    that sandbox by loading accounts.firefox.com in that process and forcing a log-in to a malicious Firefox
    Sync account. Preference settings that disable the sandbox are then synchronized to the local machine and
    the compromised browser would restart without the sandbox if a crash is triggered. This vulnerability
    affects Firefox ESR < 60.9, Firefox ESR < 68.1, and Firefox < 69. (CVE-2019-9812)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 68, Firefox ESR
    68, and Firefox 60.8. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects
    Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
    (CVE-2019-11740)

  - A same-origin policy violation occurs allowing the theft of cross-origin images through a combination of
    SVG filters and a <canvas> element due to an error in how same-origin policy is applied to cached
    image content. The resulting same-origin policy violation could allow for data theft. This vulnerability
    affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1.
    (CVE-2019-11742)

  - Navigation events were not fully adhering to the W3C's Navigation-Timing Level 2 draft specification in
    some instances for the unload event, which restricts access to detailed timing attributes to only be same-
    origin. This resulted in potential cross-origin information exposure of history through timing side-
    channel attacks. This vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox
    ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11743)

  - Some HTML elements, such as <title> and <textarea>, can contain literal angle brackets without
    treating them as markup. It is possible to pass a literal closing tag to .innerHTML on these elements, and
    subsequent content after that will be parsed as if it were outside the tag. This can lead to XSS if a site
    does not filter user input as strictly for these elements as it does for other elements. This
    vulnerability affects Firefox < 69, Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and
    Firefox ESR < 68.1. (CVE-2019-11744)

  - A use-after-free vulnerability can occur while manipulating video elements if the body is freed while
    still in use. This results in a potentially exploitable crash. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11746)

  - It is possible to delete an IndexedDB key value and subsequently try to extract it during conversion. This
    results in a use-after-free and a potentially exploitable crash. This vulnerability affects Firefox < 69,
    Thunderbird < 68.1, Thunderbird < 60.9, Firefox ESR < 60.9, and Firefox ESR < 68.1. (CVE-2019-11752)

  - When following the value's prototype chain, it was possible to retain a reference to a locale, delete it,
    and subsequently reference it. This resulted in a use-after-free and a potentially exploitable crash. This
    vulnerability affects Firefox < 70, Thunderbird < 68.2, and Firefox ESR < 68.2. (CVE-2019-11757)

  - Mozilla community member Philipp reported a memory safety bug present in Firefox 68 when 360 Total
    Security was installed. This bug showed evidence of memory corruption in the accessibility engine and we
    presume that with enough effort that it could be exploited to run arbitrary code. This vulnerability
    affects Firefox < 69, Thunderbird < 68.2, and Firefox ESR < 68.2. (CVE-2019-11758)

  - If two same-origin documents set document.domain differently to become cross-origin, it was possible for
    them to call arbitrary DOM methods/getters/setters on the now-cross-origin window. This vulnerability
    affects Firefox < 70, Thunderbird < 68.2, and Firefox ESR < 68.2. (CVE-2019-11762)

  - Failure to correctly handle null bytes when processing HTML entities resulted in Firefox incorrectly
    parsing these entities. This could have led to HTML comment text being treated as HTML which could have
    led to XSS in a web application under certain conditions. It could have also led to HTML entities being
    masked from filters - enabling the use of entities to mask the actual characters of interest from filters.
    This vulnerability affects Firefox < 70, Thunderbird < 68.2, and Firefox ESR < 68.2. (CVE-2019-11763)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 69 and Firefox ESR
    68.1. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could be exploited to run arbitrary code. This vulnerability affects Firefox < 70, Thunderbird <
    68.2, and Firefox ESR < 68.2. (CVE-2019-11764)

  - An attacker could have caused 4 bytes of HMAC output to be written past the end of a buffer stored on the
    stack. This could be used by an attacker to execute arbitrary code or more likely lead to a crash. This
    vulnerability affects Firefox < 70, Thunderbird < 68.2, and Firefox ESR < 68.2. (CVE-2019-11759)

  - A fixed-size stack buffer could overflow in nrappkit when doing WebRTC signaling. This resulted in a
    potentially exploitable crash in some instances. This vulnerability affects Firefox < 70, Thunderbird <
    68.2, and Firefox ESR < 68.2. (CVE-2019-11760)

  - By using a form with a data URI it was possible to gain access to the privileged JSONView object that had
    been cloned into content. Impact from exposing this object appears to be minimal, however it was a bypass
    of existing defense in depth mechanisms. This vulnerability affects Firefox < 70, Thunderbird < 68.2, and
    Firefox ESR < 68.2. (CVE-2019-11761)

  - Under certain conditions, when checking the Resist Fingerprinting preference during device orientation
    checks, a race condition could have caused a use-after-free and a potentially exploitable crash. This
    vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3, and Firefox < 71. (CVE-2019-17010)

  - Under certain conditions, when retrieving a document from a DocShell in the antitracking code, a race
    condition could cause a use-after-free condition and a potentially exploitable crash. This vulnerability
    affects Thunderbird < 68.3, Firefox ESR < 68.3, and Firefox < 71. (CVE-2019-17011)

  - Mozilla developers reported memory safety bugs present in Firefox 70 and Firefox ESR 68.2. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3,
    and Firefox < 71. (CVE-2019-17012)

  - When using nested workers, a use-after-free could occur during worker destruction. This resulted in a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-17008)

  - The plain text serializer used a fixed-size array for the number of  elements it could process;
    however it was possible to overflow the static-sized array leading to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3, and Firefox < 71.
    (CVE-2019-17005)

  - By carefully crafting promise resolutions, it was possible to cause an out-of-bounds read off the end of
    an array resized during script execution. This could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 68.6, Firefox < 74, Firefox < ESR68.6, and
    Firefox ESR < 68.6. (CVE-2020-6806)

  - In certain circumstances, the MCallGetProperty opcode can be emitted with unmet assumptions resulting in
    an exploitable use-after-free condition. This vulnerability affects Firefox < 82.0.3, Firefox ESR <
    78.4.1, and Thunderbird < 78.4.2. (CVE-2020-26950)

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

  - A content process could have modified shared memory relating to crash reporting information, crash itself,
    and cause an out-of-bound write. This could have caused memory corruption and a potentially exploitable
    crash. This vulnerability affects Firefox < 73 and Firefox < ESR68.5. (CVE-2020-6796)

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

  - Mozilla developers reported memory safety bugs present in Firefox 76 and Firefox ESR 68.8. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and
    Firefox ESR < 68.9. (CVE-2020-12410)

  - Mozilla Developer Iain Ireland discovered a missing type check during unboxed objects removal, resulting
    in a crash. We presume that with enough effort that it could be exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR < 68.9. (CVE-2020-12406)

  - When browsing a malicious page, a race condition in our SharedWorkerService could occur and lead to a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox
    ESR < 68.9. (CVE-2020-12405)

  - Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process
    memory to malicious JavaScript. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12418)

  - When processing callbacks that occurred during window flushing in the parent process, the associated
    window may die; causing a use-after-free condition. This could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12419)

  - When trying to connect to a STUN server, a race condition could have caused a use-after-free of a pointer,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox ESR <
    68.10, Firefox < 78, and Thunderbird < 68.10.0. (CVE-2020-12420)

  - When performing add-on updates, certificate chains terminating in non-built-in-roots were rejected (even
    if they were legitimately added by an administrator.) This could have caused add-ons to become out-of-date
    silently without notification to the user. This vulnerability affects Firefox ESR < 68.10, Firefox < 78,
    and Thunderbird < 68.10.0. (CVE-2020-12421)

  - Use after free in ANGLE in Google Chrome prior to 81.0.4044.122 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6463)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a
    privileged network position to potentially exploit heap corruption via a crafted SCTP stream.
    (CVE-2020-6514)

  - By observing the stack trace for JavaScript errors in web workers, it was possible to leak the result of a
    cross-origin redirect. This applied only to content that can be parsed as script. This vulnerability
    affects Firefox < 79, Firefox ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird <
    78.1. (CVE-2020-15652)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 78 and Firefox ESR
    78.0. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 79, Firefox
    ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird < 78.1. (CVE-2020-15659)

  - By holding a reference to the eval() function from an about:blank window, a malicious webpage could have
    gained access to the InstallTrigger object which would allow them to prompt the user to install an
    extension. Combined with user confusion, this could result in an unintended or malicious extension being
    installed. This vulnerability affects Firefox < 80, Thunderbird < 78.2, Thunderbird < 68.12, Firefox ESR <
    68.12, Firefox ESR < 78.2, and Firefox for Android < 80. (CVE-2020-15664)

  - When aborting an operation, such as a fetch, an abort signal may be deleted while alerting the objects to
    be notified. This results in a use-after-free and we presume that with enough effort it could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 68.12 and Thunderbird < 68.12.
    (CVE-2020-15669)

  - By exploiting an Open Redirect vulnerability on a website, an attacker could have spoofed the site
    displayed in the download file dialog to show the original site (the one suffering from the open redirect)
    rather than the site the file was actually downloaded from. This vulnerability affects Firefox < 81,
    Thunderbird < 78.3, and Firefox ESR < 78.3. (CVE-2020-15677)

  - Firefox sometimes ran the onload handler for SVG elements that the DOM sanitizer decided to remove,
    resulting in JavaScript being executed after pasting attacker-controlled data into a contenteditable
    element. This vulnerability affects Firefox < 81, Thunderbird < 78.3, and Firefox ESR < 78.3.
    (CVE-2020-15676)

  - When recursing through graphical layers while scrolling, an iterator may have become invalid, resulting in
    a potential use-after-free. This occurs because the function
    APZCTreeManager::ComputeClippedCompositionBounds did not follow iterator invalidation rules. This
    vulnerability affects Firefox < 81, Thunderbird < 78.3, and Firefox ESR < 78.3. (CVE-2020-15678)

  - Mozilla developers reported memory safety bugs present in Firefox 80 and Firefox ESR 78.2. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 81, Thunderbird < 78.3, and
    Firefox ESR < 78.3. (CVE-2020-15673)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 81 and Firefox ESR
    78.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.4,
    Firefox < 82, and Thunderbird < 78.4. (CVE-2020-15683)

  - Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15969)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12395");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox MCallGetProperty Write Side Effects Use After Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 4.06': [
    'firefox-78.5.0-1.el6.centos'
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
