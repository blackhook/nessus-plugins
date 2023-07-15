#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5824-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171009);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

  script_cve_id(
    "CVE-2022-45403",
    "CVE-2022-45404",
    "CVE-2022-45405",
    "CVE-2022-45406",
    "CVE-2022-45408",
    "CVE-2022-45409",
    "CVE-2022-45410",
    "CVE-2022-45411",
    "CVE-2022-45412",
    "CVE-2022-45414",
    "CVE-2022-45416",
    "CVE-2022-45418",
    "CVE-2022-45420",
    "CVE-2022-45421",
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605"
  );
  script_xref(name:"USN", value:"5824-1");
  script_xref(name:"IAVA", value:"2023-A-0056-S");
  script_xref(name:"IAVA", value:"2022-A-0519-S");
  script_xref(name:"IAVA", value:"2022-A-0492-S");
  script_xref(name:"IAVA", value:"2022-A-0505-S");
  script_xref(name:"IAVA", value:"2023-A-0009-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Thunderbird vulnerabilities (USN-5824-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5824-1 advisory.

  - Service Workers should not be able to infer information about opaque cross-origin responses; but timing
    information for cross-origin media combined with Range requests might have allowed them to determine the
    presence or length of a media file. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5,
    and Firefox < 107. (CVE-2022-45403)

  - Through a series of popup and <code>window.print()</code> calls, an attacker can cause a window to go
    fullscreen without the user seeing the notification prompt, resulting in potential user confusion or
    spoofing attacks. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107.
    (CVE-2022-45404)

  - Freeing arbitrary <code>nsIInputStream</code>'s on a different thread than creation could have led to a
    use-after-free and potentially exploitable crash. This vulnerability affects Firefox ESR < 102.5,
    Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45405)

  - If an out-of-memory condition occurred when creating a JavaScript global, a JavaScript realm may be
    deleted while references to it lived on in a BaseShape. This could lead to a use-after-free causing a
    potentially exploitable crash. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and
    Firefox < 107. (CVE-2022-45406)

  - Through a series of popups that reuse windowName, an attacker can cause a window to go fullscreen without
    the user seeing the notification prompt, resulting in potential user confusion or spoofing attacks. This
    vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45408)

  - The garbage collector could have been aborted in several states and zones and
    <code>GCRuntime::finishCollection</code> may not have been called, leading to a use-after-free and
    potentially exploitable crash. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and
    Firefox < 107. (CVE-2022-45409)

  - When a ServiceWorker intercepted a request with <code>FetchEvent</code>, the origin of the request was
    lost after the ServiceWorker took ownership of it. This had the effect of negating SameSite cookie
    protections. This was addressed in the spec and then in browsers. This vulnerability affects Firefox ESR <
    102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45410)

  - Cross-Site Tracing occurs when a server will echo a request back via the Trace method, allowing an XSS
    attack to access to authorization headers and cookies inaccessible to JavaScript (such as cookies
    protected by HTTPOnly). To mitigate this attack, browsers placed limits on <code>fetch()</code> and
    XMLHttpRequest; however some webservers have implemented non-standard headers such as <code>X-Http-Method-
    Override</code> that override the HTTP method, and made this attack possible again. Thunderbird has
    applied the same mitigations to the use of this and similar headers. This vulnerability affects Firefox
    ESR < 102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45411)

  - When resolving a symlink such as <code>file:///proc/self/fd/1</code>, an error message may be produced
    where the symlink was resolved to a string containing unitialized memory in the buffer. <br>*This bug only
    affects Thunderbird on Unix-based operated systems (Android, Linux, MacOS). Windows is unaffected.*. This
    vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45412)

  - If a Thunderbird user quoted from an HTML email, for example by replying to the email, and the email
    contained either a VIDEO tag with the POSTER attribute or an OBJECT tag with a DATA attribute, a network
    request to the referenced remote URL was performed, regardless of a configuration to block remote content.
    An image loaded from the POSTER attribute was shown in the composer window. These issues could have given
    an attacker additional capabilities when targetting releases that did not yet have a fix for CVE-2022-3033
    which was reported around three months ago. This vulnerability affects Thunderbird < 102.5.1.
    (CVE-2022-45414)

  - Keyboard events reference strings like KeyA that were at fixed, known, and widely-spread addresses.
    Cache-based timing attacks such as Prime+Probe could have possibly figured out which keys were being
    pressed. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107.
    (CVE-2022-45416)

  - If a custom mouse cursor is specified in CSS, under certain circumstances the cursor could have been drawn
    over the browser UI, resulting in potential user confusion or spoofing attacks. This vulnerability affects
    Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45418)

  - Use tables inside of an iframe, an attacker could have caused iframe contents to be rendered outside the
    boundaries of the iframe, resulting in potential user confusion or spoofing attacks. This vulnerability
    affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45420)

  - Mozilla developers Andrew McCreight and Gabriele Svelto reported memory safety bugs present in Thunderbird
    102.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.5,
    Thunderbird < 102.5, and Firefox < 107. (CVE-2022-45421)

  - An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited. This
    vulnerability affects Firefox < 108. (CVE-2022-46871)

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages.<br>*This bug only affects Thunderbird for Linux. Other operating
    systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird <
    102.6. (CVE-2022-46872)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could potentially led to user confusion and the execution of
    malicious code.<br/>*Note*: This issue was originally included in the advisories for Thunderbird 102.6,
    but a patch (specific to Thunderbird) was omitted, resulting in it actually being fixed in Thunderbird
    102.6.1. This vulnerability affects Firefox < 108, Thunderbird < 102.6.1, Thunderbird < 102.6, and Firefox
    ESR < 102.6. (CVE-2022-46874)

  - By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in
    potential user confusion or spoofing attacks. This vulnerability affects Firefox < 108. (CVE-2022-46877)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Thunderbird 102.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46878)

  - A missing check related to tex units could have led to a use-after-free and potentially exploitable
    crash.<br />*Note*: This advisory was added on December 13th, 2022 after we better understood the impact
    of the issue. The fix was included in the original release of Firefox 105. This vulnerability affects
    Firefox ESR < 102.6, Firefox < 105, and Thunderbird < 102.6. (CVE-2022-46880)

  - An optimization in WebGL was incorrect in some cases, and could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox < 106, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46881)

  - A use-after-free in WebGL extensions could have led to a potentially exploitable crash. This vulnerability
    affects Firefox < 107, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46882)

  - Mozilla: Arbitrary file read from GTK drag and drop on Linux (CVE-2023-23598)

  - Mozilla: Malicious command could be hidden in devtools output (CVE-2023-23599)

  - Mozilla: URL being dragged from cross-origin iframe into same tab triggers navigation (CVE-2023-23601)

  - Mozilla: Content Security Policy wasn't being correctly applied to WebSockets in WebWorkers
    (CVE-2023-23602)

  - Mozilla: Calls to <code>console.log</code> allowed bypasing Content Security Policy via format directive
    (CVE-2023-23603)

  - Mozilla: Memory safety bugs fixed in Firefox 109 and Firefox ESR 102.7 (CVE-2023-23605)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5824-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-ta-lk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-locale-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-mozsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-calendar-timezones");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-gdata-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-lightning");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.7.1+build2-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.7.1+build2-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-dev', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-gnome-support', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-af', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ast', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-be', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bg', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-bn-bd', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ca', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cak', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cs', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-cy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-da', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-de', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-dsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-el', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en-gb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-en-us', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es-ar', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-es-es', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-et', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-eu', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fa', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fi', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-fy-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ga', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ga-ie', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-gd', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-gl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-he', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hsb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hu', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-hy', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-id', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-is', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-it', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ja', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ka', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-kab', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-kk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ko', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-lt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-lv', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-mk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ms', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nb', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nb-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-nn-no', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pa', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pa-in', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt-br', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-pt-pt', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-rm', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ro', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ru', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-si', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sl', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sq', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sv', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-sv-se', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ta', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-ta-lk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-th', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-tr', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-uk', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-uz', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-vi', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-cn', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-hans', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-hant', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-locale-zh-tw', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'thunderbird-mozsymbols', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-calendar-timezones', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-gdata-provider', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'},
    {'osver': '22.10', 'pkgname': 'xul-ext-lightning', 'pkgver': '1:102.7.1+build2-0ubuntu0.22.10.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-dev / thunderbird-gnome-support / etc');
}
