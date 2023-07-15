#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-35.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176481);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id(
    "CVE-2023-0767",
    "CVE-2023-1945",
    "CVE-2023-1999",
    "CVE-2023-25728",
    "CVE-2023-25729",
    "CVE-2023-25730",
    "CVE-2023-25731",
    "CVE-2023-25732",
    "CVE-2023-25734",
    "CVE-2023-25735",
    "CVE-2023-25737",
    "CVE-2023-25738",
    "CVE-2023-25739",
    "CVE-2023-25742",
    "CVE-2023-25746",
    "CVE-2023-25748",
    "CVE-2023-25749",
    "CVE-2023-25750",
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28159",
    "CVE-2023-28160",
    "CVE-2023-28161",
    "CVE-2023-28162",
    "CVE-2023-28163",
    "CVE-2023-28164",
    "CVE-2023-28176",
    "CVE-2023-28177",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29537",
    "CVE-2023-29538",
    "CVE-2023-29539",
    "CVE-2023-29540",
    "CVE-2023-29541",
    "CVE-2023-29543",
    "CVE-2023-29544",
    "CVE-2023-29547",
    "CVE-2023-29548",
    "CVE-2023-29549",
    "CVE-2023-29550",
    "CVE-2023-29551"
  );

  script_name(english:"GLSA-202305-35 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-35 (Mozilla Firefox: Multiple Vulnerabilities)

  - An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory
    writes via PKCS 12 Safe Bag attributes being mishandled.  (CVE-2023-0767)

  - Unexpected data returned from the Safe Browsing API could have led to memory corruption and a potentially
    exploitable crash.  (CVE-2023-1945)

  - A double-free in libwebp could have led to memory corruption and a potentially exploitable crash.
    (CVE-2023-1999)

  - Mozilla: Content security policy leak in violation reports using iframes (CVE-2023-25728)

  - Permission prompts for opening external schemes were only shown for <code>ContentPrincipals</code>
    resulting in extensions being able to open them without user interaction via
    <code>ExpandedPrincipals</code>. This could lead to further malicious actions such as downloading files or
    interacting with software already installed on the system.  (CVE-2023-25729)

  - A background script invoking <code>requestFullscreen</code> and then blocking the main thread could force
    the browser into fullscreen mode indefinitely, resulting in potential user confusion or spoofing attacks.
    (CVE-2023-25730)

  - Due to URL previews in the network panel of developer tools improperly storing URLs, query parameters
    could potentially be used to overwrite global objects in privileged code.  (CVE-2023-25731)

  - When encoding data from an <code>inputStream</code> in <code>xpcom</code> the size of the input being
    encoded was not correctly calculated potentially leading to an out of bounds memory write.
    (CVE-2023-25732)

  - After downloading a Windows <code>.url</code> shortcut from the local filesystem, an attacker could supply
    a remote path that would lead to unexpected network requests from the operating system.  This also had the
    potential to leak NTLM credentials to the resource. This bug only affects Thunderbird on Windows. Other
    operating systems are unaffected.  (CVE-2023-25734)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free after unwrapping the proxy.
    (CVE-2023-25735)

  - An invalid downcast from <code>nsTextNode</code> to <code>SVGElement</code> could have lead to undefined
    behavior.  (CVE-2023-25737)

  - Members of the <code>DEVMODEW</code> struct set by the printer device driver weren't being validated and
    could have resulted in invalid values which in turn would cause the browser to attempt out of bounds
    access to related variables. This bug only affects Thunderbird on Windows. Other operating systems are
    unaffected.  (CVE-2023-25738)

  - Module load requests that failed were not being checked as to whether or not they were cancelled causing a
    use-after-free in <code>ScriptLoadContext</code>.  (CVE-2023-25739)

  - When importing a SPKI RSA public key as ECDSA P-256, the key would be handled incorrectly causing the tab
    to crash.  (CVE-2023-25742)

  - Mozilla developers Philipp and Gabriele Svelto reported memory safety bugs present in Thunderbird 102.7.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code.  (CVE-2023-25746)

  - By displaying a prompt with a long description, the fullscreen notification could have been hidden,
    resulting in potential user confusion or spoofing attacks.  This bug only affects Firefox for Android.
    Other operating systems are unaffected.  (CVE-2023-25748)

  - Android applications with unpatched vulnerabilities can be launched from a browser using Intents, exposing
    users to these vulnerabilities. Firefox will now confirm with users that they want to launch an external
    application before doing so.  This bug only affects Firefox for Android. Other versions of Firefox are
    unaffected.  (CVE-2023-25749)

  - Under certain circumstances, a ServiceWorker's offline cache may have leaked to the file system when using
    private browsing mode.  (CVE-2023-25750)

  - Mozilla: Incorrect code generation during JIT compilation (CVE-2023-25751)

  - Mozilla: Potential out-of-bounds when accessing throttled streams (CVE-2023-25752)

  - The fullscreen notification could have been hidden on Firefox for Android by using download popups,
    resulting in potential user confusion or spoofing attacks.  This bug only affects Firefox for Android.
    Other operating systems are unaffected.  (CVE-2023-28159)

  - When following a redirect to a publicly accessible web extension file, the URL may have been translated to
    the actual local path, leaking potentially sensitive information.  (CVE-2023-28160)

  - If temporary one-time permissions, such as the ability to use the Camera, were granted to a document
    loaded using a file: URL, that permission persisted in that tab for all other documents loaded from a
    file: URL. This is potentially dangerous if the local files came from different sources, such as in a
    download directory.  (CVE-2023-28161)

  - Mozilla: Invalid downcast in Worklets (CVE-2023-28162)

  - When downloading files through the Save As dialog on Windows with suggested filenames containing
    environment variable names, Windows would have resolved those in the context of the current user.  This
    bug only affects Firefox on Windows. Other versions of Firefox are unaffected.  (CVE-2023-28163)

  - Mozilla: URL being dragged from a removed cross-origin iframe into the same tab triggered navigation
    (CVE-2023-28164)

  - Mozilla: Memory safety bugs fixed in Firefox 111 and Firefox ESR 102.9 (CVE-2023-28176)

  - Mozilla developers and community members Calixte Denizet, Gabriele Svelto, Andrew McCreight, and the
    Mozilla Fuzzing Team reported memory safety bugs present in Firefox 110. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-28177)

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks.
    (CVE-2023-29533)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash.  (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.
    (CVE-2023-29536)

  - Multiple race conditions in the font initialization could have led to memory corruption and execution of
    attacker-controlled code.  (CVE-2023-29537)

  - Under specific circumstances a WebExtension may have received a <code>jar:file:///</code> URI instead of a
    <code>moz-extension:///</code> URI during a load request. This leaked directory paths on the user's
    machine.  (CVE-2023-29538)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware.  (CVE-2023-29539)

  - Using a redirect embedded into <code>sourceMappingUrls</code> could allow for navigation to external
    protocol links in sandboxed iframes without <code>allow-top-navigation-to-custom-protocols</code>.
    (CVE-2023-29540)

  - Thunderbird did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands.  This bug only affects Thunderbird for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions.  (CVE-2023-29541)

  - An attacker could have caused memory corruption and a potentially exploitable use-after-free of a pointer
    in a global object's debugger vector.  (CVE-2023-29543)

  - If multiple instances of resource exhaustion occurred at the incorrect time, the garbage collector could
    have caused memory corruption and a potentially exploitable crash.  (CVE-2023-29544)

  - When a secure cookie existed in the Firefox cookie jar an insecure cookie for the same domain could have
    been created, when it should have silently failed.  This could have led to a desynchronization in expected
    results when reading from the secure cookie.  (CVE-2023-29547)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result.
    (CVE-2023-29548)

  - Under certain circumstances, a call to the <code>bind</code> function may have resulted in the incorrect
    realm.  This may have created a vulnerability relating to JavaScript-implemented sandboxes such as SES.
    (CVE-2023-29549)

  - Mozilla developers Andrew Osmond, Sebastian Hengst, Andrew McCreight, and the Mozilla Fuzzing Team
    reported memory safety bugs present in Thunderbird 102.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2023-29550)

  - Mozilla developers Randell Jesup, Andrew McCreight, Gabriele Svelto, and the Mozilla Fuzzing Team reported
    memory safety bugs present in Firefox 111. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2023-29551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-35");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=895962");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903618");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=905889");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-102.10.0:esr
        
All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-102.10.0:esr
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-112.0:rapid
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-112.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 102.10.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.10.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 112.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 112.0", "ge 103.0.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 102.10.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.10.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 112.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 112.0", "ge 103.0.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
