#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202211-06.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(168048);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id(
    "CVE-2022-40674",
    "CVE-2022-45403",
    "CVE-2022-45404",
    "CVE-2022-45405",
    "CVE-2022-45406",
    "CVE-2022-45407",
    "CVE-2022-45408",
    "CVE-2022-45409",
    "CVE-2022-45410",
    "CVE-2022-45411",
    "CVE-2022-45412",
    "CVE-2022-45413",
    "CVE-2022-45415",
    "CVE-2022-45416",
    "CVE-2022-45417",
    "CVE-2022-45418",
    "CVE-2022-45419",
    "CVE-2022-45420",
    "CVE-2022-45421"
  );

  script_name(english:"GLSA-202211-06 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202211-06 (Mozilla Firefox: Multiple Vulnerabilities)

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

  - Service Workers should not be able to infer information about opaque cross-origin responses; but timing
    information for cross-origin media combined with Range requests might have allowed them to determine the
    presence or length of a media file.  (CVE-2022-45403)

  - Through a series of popup and <code>window.print()</code> calls, an attacker can cause a window to go
    fullscreen without the user seeing the notification prompt, resulting in potential user confusion or
    spoofing attacks.  (CVE-2022-45404)

  - Freeing arbitrary <code>nsIInputStream</code>'s on a different thread than creation could have led to a
    use-after-free and potentially exploitable crash.  (CVE-2022-45405)

  - If an out-of-memory condition occurred when creating a JavaScript global, a JavaScript realm may be
    deleted while references to it lived on in a BaseShape. This could lead to a use-after-free causing a
    potentially exploitable crash.  (CVE-2022-45406)

  - If an attacker loaded a font using <code>FontFace()</code> on a background worker, a use-after-free could
    have occurred, leading to a potentially exploitable crash.  (CVE-2022-45407)

  - Through a series of popups that reuse windowName, an attacker can cause a window to go fullscreen without
    the user seeing the notification prompt, resulting in potential user confusion or spoofing attacks.
    (CVE-2022-45408)

  - The garbage collector could have been aborted in several states and zones and
    <code>GCRuntime::finishCollection</code> may not have been called, leading to a use-after-free and
    potentially exploitable crash  (CVE-2022-45409)

  - When a ServiceWorker intercepted a request with <code>FetchEvent</code>, the origin of the request was
    lost after the ServiceWorker took ownership of it.  This had the effect of negating SameSite cookie
    protections.  This was addressed in the spec and then in browsers.  (CVE-2022-45410)

  - Cross-Site Tracing occurs when a server will echo a request back via the Trace method, allowing an XSS
    attack to access to authorization headers and cookies inaccessible to JavaScript (such as cookies
    protected by HTTPOnly).  To mitigate this attack, browsers placed limits on <code>fetch()</code> and
    XMLHttpRequest; however some webservers have implemented non-standard headers such as <code>X-Http-Method-
    Override</code> that override the HTTP method, and made this attack possible again.  Firefox has applied
    the same mitigations to the use of this and similar headers.  (CVE-2022-45411)

  - When resolving a symlink such as <code>file:///proc/self/fd/1</code>, an error message may be produced
    where the symlink was resolved to a string containing unitialized memory in the buffer.  This bug only
    affects Thunderbird on Unix-based operated systems (Android, Linux, MacOS). Windows is unaffected.
    (CVE-2022-45412)

  - Using the <code>S.browserfallbackurl parameter</code> parameter, an attacker could redirect a user to a
    URL and cause SameSite=Strict cookies to be sent. This issue only affects Firefox for Android. Other
    operating systems are not affected.  (CVE-2022-45413)

  - When downloading an HTML file, if the title of the page was formatted as a filename with a malicious
    extension, Firefox may have saved the file with that extension, leading to possible system compromise if
    the downloaded file was later ran.  (CVE-2022-45415)

  - Keyboard events reference strings like KeyA that were at fixed, known, and widely-spread addresses.
    Cache-based timing attacks such as Prime+Probe could have possibly figured out which keys were being
    pressed.  (CVE-2022-45416)

  - Service Workers did not detect Private Browsing Mode correctly in all cases, which could have led to
    Service Workers being written to disk for websites visited in Private Browsing Mode.  This would not have
    persisted them in a state where they would run again, but it would have leaked Private Browsing Mode
    details to disk.  (CVE-2022-45417)

  - If a custom mouse cursor is specified in CSS, under certain circumstances the cursor could have been drawn
    over the browser UI, resulting in potential user confusion or spoofing attacks.  (CVE-2022-45418)

  - If the user added a security exception for an invalid TLS certificate, opened an ongoing TLS connection
    with a server that used that certificate, and then deleted the exception, Firefox would have kept the
    connection alive, making it seem like the certificate was still trusted.  (CVE-2022-45419)

  - Use tables inside of an iframe, an attacker could have caused iframe contents to be rendered outside the
    boundaries of the iframe, resulting in potential user confusion or spoofing attacks.  (CVE-2022-45420)

  - Mozilla developers Andrew McCreight and Gabriele Svelto reported memory safety bugs present in Firefox 106
    and Firefox ESR 102.4. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-45421)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202211-06");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881403");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-102.5.0
        
All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-102.5.0
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-107.0
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-107.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

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
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 102.5.0"),
    'vulnerable' : make_list("lt 102.5.0", "ge 103.0.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 107.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 107.0", "ge 103.0.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 102.5.0"),
    'vulnerable' : make_list("lt 102.5.0", "ge 103.0.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 107.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 107.0", "ge 103.0.0")
  }
];

foreach package( packages ) {
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
