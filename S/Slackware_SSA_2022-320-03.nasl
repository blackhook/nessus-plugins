#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-320-03. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167777);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

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
    "CVE-2022-45416",
    "CVE-2022-45418",
    "CVE-2022-45420",
    "CVE-2022-45421"
  );
  script_xref(name:"IAVA", value:"2022-A-0492-S");

  script_name(english:"Slackware Linux 15.0 / current mozilla-thunderbird  Multiple Vulnerabilities (SSA:2022-320-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-thunderbird.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-thunderbird installed on the remote host is prior to 102.5.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2022-320-03 advisory.

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

  - Keyboard events reference strings like KeyA that were at fixed, known, and widely-spread addresses.
    Cache-based timing attacks such as Prime+Probe could have possibly figured out which keys were being
    pressed.  (CVE-2022-45416)

  - If a custom mouse cursor is specified in CSS, under certain circumstances the cursor could have been drawn
    over the browser UI, resulting in potential user confusion or spoofing attacks.  (CVE-2022-45418)

  - Use tables inside of an iframe, an attacker could have caused iframe contents to be rendered outside the
    boundaries of the iframe, resulting in potential user confusion or spoofing attacks.  (CVE-2022-45420)

  - Mozilla developers Andrew McCreight and Gabriele Svelto reported memory safety bugs present in Firefox 106
    and Firefox ESR 102.4. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-45421)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45421");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '102.5.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '102.5.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '102.5.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '102.5.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
