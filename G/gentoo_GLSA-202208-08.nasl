#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-08.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164149);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id(
    "CVE-2022-0843",
    "CVE-2022-1196",
    "CVE-2022-1529",
    "CVE-2022-1802",
    "CVE-2022-1919",
    "CVE-2022-2200",
    "CVE-2022-2505",
    "CVE-2022-24713",
    "CVE-2022-26381",
    "CVE-2022-26382",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26385",
    "CVE-2022-26386",
    "CVE-2022-26387",
    "CVE-2022-26485",
    "CVE-2022-26486",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28283",
    "CVE-2022-28284",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28287",
    "CVE-2022-28288",
    "CVE-2022-28289",
    "CVE-2022-29909",
    "CVE-2022-29910",
    "CVE-2022-29911",
    "CVE-2022-29912",
    "CVE-2022-29914",
    "CVE-2022-29915",
    "CVE-2022-29916",
    "CVE-2022-29917",
    "CVE-2022-29918",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31743",
    "CVE-2022-31744",
    "CVE-2022-31745",
    "CVE-2022-31747",
    "CVE-2022-31748",
    "CVE-2022-34468",
    "CVE-2022-34469",
    "CVE-2022-34470",
    "CVE-2022-34471",
    "CVE-2022-34472",
    "CVE-2022-34473",
    "CVE-2022-34474",
    "CVE-2022-34475",
    "CVE-2022-34476",
    "CVE-2022-34477",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34480",
    "CVE-2022-34481",
    "CVE-2022-34482",
    "CVE-2022-34483",
    "CVE-2022-34484",
    "CVE-2022-34485",
    "CVE-2022-36315",
    "CVE-2022-36316",
    "CVE-2022-36318",
    "CVE-2022-36319",
    "CVE-2022-36320"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");

  script_name(english:"GLSA-202208-08 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-08 (Mozilla Firefox: Multiple Vulnerabilities)

  - Use after free in Codecs in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1919)

  - regex is an implementation of regular expressions for the Rust language. The regex crate features built-in
    mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched
    by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This
    guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in
    the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing,
    and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial
    of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted
    regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is
    include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade
    immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic
    regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability.
    Because of this, it us not recommend to deny known problematic regexes. (CVE-2022-24713)

  - Mozilla developers Kershaw Chang, Ryan VanderMeulen, and Randell Jesup reported memory safety bugs present
    in Firefox 97. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code.  (CVE-2022-0843)

  - After a VR Process is destroyed, a reference to it may have been retained and used, leading to a use-
    after-free and potentially exploitable crash.  (CVE-2022-1196)

  - Mozilla: Untrusted input used in JavaScript object indexing, leading to prototype pollution
    (CVE-2022-1529)

  - If an attacker was able to corrupt the methods of an Array object in JavaScript via prototype pollution,
    they could have achieved execution of attacker-controlled JavaScript code in a privileged context.
    (CVE-2022-1802)

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution.  (CVE-2022-2200)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird 102.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code.  (CVE-2022-2505)

  - An attacker could have caused a use-after-free by forcing a text reflow in an SVG object leading to a
    potentially exploitable crash.  (CVE-2022-26381)

  - While the text displayed in Autofill tooltips cannot be directly read by JavaScript, the text was rendered
    using page fonts. Side-channel attacks on the text by using specially crafted fonts could have lead to
    this text being inferred by the webpage.  (CVE-2022-26382)

  - Mozilla: Browser window spoof using fullscreen mode (CVE-2022-26383, CVE-2022-31738)

  - If an attacker could control the contents of an iframe sandboxed with <code>allow-popups</code> but not
    <code>allow-scripts</code>, they were able to craft a link that, when clicked, would lead to JavaScript
    execution in violation of the sandbox.  (CVE-2022-26384)

  - In unusual circumstances, an individual thread may outlive the thread's manager during shutdown.  This
    could have led to a use-after-free causing a potentially exploitable crash.  (CVE-2022-26385)

  - Previously Thunderbird for macOS and Linux would download temporary files to a user-specific directory in
    <code>/tmp</code>, but this behavior was changed to download them to <code>/tmp</code> where they could be
    affected by other local users.  This behavior was reverted to the original, user-specific directory.  This
    bug only affects Thunderbird for macOS and Linux. Other operating systems are unaffected.
    (CVE-2022-26386)

  - When installing an add-on, Thunderbird verified the signature before prompting the user; but while the
    user was confirming the prompt, the underlying add-on file could have been modified and Thunderbird would
    not have noticed.  (CVE-2022-26387)

  - Removing an XSLT parameter during processing could have lead to an exploitable use-after-free. We have had
    reports of attacks in the wild abusing this flaw.  (CVE-2022-26485)

  - An unexpected message in the WebGPU IPC framework could lead to a use-after-free and exploitable sandbox
    escape.  We have had reports of attacks in the wild abusing this flaw.  (CVE-2022-26486)

  - If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to
    the parent process, an out of bounds write would have occurred leading to memory corruption and a
    potentially exploitable crash.  (CVE-2022-28281)

  - By using a link with <code>rel=localization</code> a use-after-free could have been triggered by
    destroying an object during JavaScript execution and then referencing the object through a freed pointer,
    leading to a potential exploitable crash.  (CVE-2022-28282)

  - The sourceMapURL feature in devtools was missing security checks that would have allowed a webpage to
    attempt to include local files or other files that should have been inaccessible.  (CVE-2022-28283)

  - SVG's <code><use></code> element could have been used to load unexpected content that could have
    executed script in certain circumstances. While the specification seems to allow this, other browsers do
    not, and web developers relied on this property for script security so gecko's implementation was aligned
    with theirs.  (CVE-2022-28284)

  - When generating the assembly code for <code>MLoadTypedArrayElementHole</code>, an incorrect AliasSet was
    used. In conjunction with another vulnerability this could have been used for an out of bounds memory
    read.  (CVE-2022-28285)

  - Due to a layout change, iframe contents could have been rendered outside of its border. This could have
    led to user confusion or spoofing attacks.  (CVE-2022-28286)

  - In unusual circumstances, selecting text could cause text selection caching to behave incorrectly, leading
    to a crash.  (CVE-2022-28287)

  - Mozilla developers and community members Randell Jesup, Sebastian Hengst, and the Mozilla Fuzzing Team
    reported memory safety bugs present in Firefox 98. Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2022-28288)

  - Mozilla developers and community members Nika Layzell, Andrew McCreight, Gabriele Svelto, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Thunderbird 91.7. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code.  (CVE-2022-28289)

  - Documents in deeply-nested cross-origin browsing contexts could obtain permissions granted to the top-
    level origin, bypassing the existing prompt and wrongfully inheriting the top-level permissions.
    (CVE-2022-29909)

  - When closed or sent to the background, Firefox for Android would not properly record and persist HSTS
    settings. Note: This issue only affected Firefox for Android. Other operating systems are unaffected.
    (CVE-2022-29910)

  - An improper implementation of the new iframe sandbox keyword <code>allow-top-navigation-by-user-
    activation</code> could lead to script execution without <code>allow-scripts</code> being present.
    (CVE-2022-29911)

  - Requests initiated through reader mode did not properly omit cookies with a SameSite attribute.
    (CVE-2022-29912)

  - When reusing existing popups Thunderbird would allow them to cover the fullscreen notification UI, which
    could enable browser spoofing attacks.  (CVE-2022-29914)

  - The Performance API did not properly hide the fact whether a request cross-origin resource has observed
    redirects.  (CVE-2022-29915)

  - Thunderbird would behave slightly differently for already known resources, when loading CSS resources
    through resolving CSS variables. This could be used to probe the browser history.  (CVE-2022-29916)

  - Mozilla developers Gabriele Svelto, Tom Ritter and the Mozilla Fuzzing Team reported memory safety bugs
    present in Thunderbird 91.8. Some of these bugs showed evidence of memory corruption and we presume that
    with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-29917)

  - Mozilla developers Gabriele Svelto, Randell Jesup and the Mozilla Fuzzing Team reported memory safety bugs
    present in Firefox 99. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-29918)

  - Mozilla: Cross-Origin resource's length leaked (CVE-2022-31736)

  - A malicious webpage could have caused an out-of-bounds write in WebGL, leading to memory corruption and a
    potentially exploitable crash.  (CVE-2022-31737)

  - On arm64, WASM code could have resulted in incorrect assembly generation leading to a register allocation
    problem, and a potentially exploitable crash.  (CVE-2022-31740)

  - Mozilla: Uninitialized variable leads to invalid memory read (CVE-2022-31741)

  - Mozilla: Querying a WebAuthn token with a large number of allowCredential entries may have leaked cross-
    origin information (CVE-2022-31742)

  - Firefox's HTML parser did not correctly interpret HTML comment tags, resulting in an incongruity with
    other browsers. This could have been used to escape HTML comments on pages that put user-controlled data
    in them.  (CVE-2022-31743)

  - An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and
    in doing so bypass a page's Content Security Policy.  (CVE-2022-31744)

  - If array shift operations are not used, the Garbage Collector may have become confused about valid
    objects.  (CVE-2022-31745)

  - Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2022-31747)

  - Mozilla developers Gabriele Svelto, Timothy Nikkel, Randell Jesup, Jon Coppeard, and the Mozilla Fuzzing
    Team reported memory safety bugs present in Firefox 100. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2022-31748)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link.  (CVE-2022-34468)

  - When a TLS Certificate error occurs on a domain protected by the HSTS header, the browser should not allow
    the user to bypass the certificate error.  On Firefox for Android, the user was presented with the option
    to bypass the error; this could only have been done by the user explicitly.  This bug only affects Firefox
    for Android. Other operating systems are unaffected.  (CVE-2022-34469)

  - Navigations between XML documents may have led to a use-after-free and potentially exploitable crash.
    (CVE-2022-34470)

  - When downloading an update for an addon, the downloaded addon update's version was not verified to match
    the version selected from the manifest.  If the manifest had been tampered with on the server, an attacker
    could trick the browser into downgrading the addon to a prior version.  (CVE-2022-34471)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown.  (CVE-2022-34472)

  - The HTML Sanitizer should have sanitized the <code>href</code> attribute of SVG <code><use></code>
    tags; however it incorrectly did not sanitize <code>xlink:href</code> attributes.  (CVE-2022-34473)

  - Even when an iframe was sandboxed with <code>allow-top-navigation-by-user-activation</code>, if it
    received a redirect header to an external protocol the browser would process the redirect and prompt the
    user as appropriate.  (CVE-2022-34474)

  - SVG <code><use></code> tags that referenced a same-origin document could have resulted in script
    execution if attacker input was sanitized via the HTML Sanitizer API. This would have required the
    attacker to reference a same-origin JavaScript file containing the script to be executed.
    (CVE-2022-34475)

  - ASN.1 parsing of an indefinite SEQUENCE inside an indefinite GROUP could have resulted in the parser
    accepting malformed ASN.1.  (CVE-2022-34476)

  - The MediaError message property should be consistent to avoid leaking information about cross-origin
    resources; however for a same-site cross-origin resource, the message could have leaked information
    enabling XS-Leaks attacks.  (CVE-2022-34477)

  - The <code>ms-msdt</code>, <code>search</code>, and <code>search-ms</code> protocols deliver content to
    Microsoft applications, bypassing the browser, when a user accepts a prompt. These applications have had
    known vulnerabilities, exploited in the wild (although we know of none exploited through Thunderbird), so
    in this release Thunderbird has blocked these protocols from prompting the user to open them. This bug
    only affects Thunderbird on Windows. Other operating systems are unaffected.  (CVE-2022-34478)

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks.   This bug only affects
    Thunderbird for Linux. Other operating systems are unaffected.  (CVE-2022-34479)

  - Within the <code>lginit()</code> function, if several allocations succeed but then one fails, an
    uninitialized pointer would have been freed despite never being allocated.  (CVE-2022-34480)

  - In the <code>nsTArrayImpl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container.  (CVE-2022-34481)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code.  While very similar, this is a separate issue from
    CVE-2022-34483.  (CVE-2022-34482)

  - An attacker who could have convinced a user to drag and drop an image to a filesystem could have
    manipulated the resulting filename to contain an executable extension, and by extension potentially
    tricked the user into executing malicious code.  While very similar, this is a separate issue from
    CVE-2022-34482.  (CVE-2022-34483)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code.  (CVE-2022-34484)

  - Mozilla developers Bryce Seager van Dyk and the Mozilla Fuzzing Team reported potential vulnerabilities
    present in Firefox 101. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-34485)

  - When loading a script with Subresource Integrity, attackers with an injection capability could trigger the
    reuse of previously cached entries with incorrect, different integrity metadata.  (CVE-2022-36315)

  - When using the Performance API, an attacker was able to notice subtle differences between
    PerformanceEntries and thus learn whether the target URL had been subject to a redirect.  (CVE-2022-36316)

  - When visiting directory listings for `chrome://` URLs as source text, some parameters were reflected.
    (CVE-2022-36318)

  - When combining CSS properties for overflow and transform, the mouse cursor could interact with different
    coordinates than displayed.  (CVE-2022-36319)

  - Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code.  (CVE-2022-36320)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-08");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834631");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834804");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=836866");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=842438");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=846593");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=849044");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=857045");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861515");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-91.12.0:esr
        
All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-91.12.0:esr
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-103.0:rapid
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-103.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1919");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-client/firefox",
    'unaffected' : make_list("ge 91.12.0", "lt 92.0"),
    'vulnerable' : make_list("lt 91.12.0")
  },
  {
    'name' : "www-client/firefox",
    'unaffected' : make_list("lt 92.0", "ge 103.0"),
    'vulnerable' : make_list("ge 92.0", "lt 103.0")
  },
  {
    'name' : "www-client/firefox-bin",
    'unaffected' : make_list("ge 91.12.0", "lt 92.0"),
    'vulnerable' : make_list("lt 91.12.0")
  },
  {
    'name' : "www-client/firefox-bin",
    'unaffected' : make_list("lt 92.0", "ge 103.0"),
    'vulnerable' : make_list("ge 92.0", "lt 103.0")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
