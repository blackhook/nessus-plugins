#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-48.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(167637);
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
  script_xref(name:"IAVA", value:"2022-A-0491-S");

  script_name(english:"Mozilla Firefox ESR < 102.5");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 102.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2022-48 advisory.

  - Service Workers should not be able to infer information about opaque cross-origin responses; but timing
    information for cross-origin media combined with Range requests might have allowed them to determine the
    presence or length of a media file. (CVE-2022-45403)

  - Through a series of popup and <code>window.print()</code> calls, an attacker can cause a window to go
    fullscreen without the user seeing the notification prompt, resulting in potential user confusion or
    spoofing attacks. (CVE-2022-45404)

  - Freeing arbitrary <code>nsIInputStream</code>'s on a different thread than creation could have led to a
    use-after-free and potentially exploitable crash. (CVE-2022-45405)

  - If an out-of-memory condition occurred when creating a JavaScript global, a JavaScript realm may be
    deleted while references to it lived on in a BaseShape. This could lead to a use-after-free causing a
    potentially exploitable crash. (CVE-2022-45406)

  - Through a series of popups that reuse windowName, an attacker can cause a window to go fullscreen without
    the user seeing the notification prompt, resulting in potential user confusion or spoofing attacks.
    (CVE-2022-45408)

  - The garbage collector could have been aborted in several states and zones and
    <code>GCRuntime::finishCollection</code> may not have been called, leading to a use-after-free and
    potentially exploitable crash (CVE-2022-45409)

  - When a ServiceWorker intercepted a request with <code>FetchEvent</code>, the origin of the request was
    lost after the ServiceWorker took ownership of it.  This had the effect of negating SameSite cookie
    protections.  This was addressed in the spec and then in browsers. (CVE-2022-45410)

  - Cross-Site Tracing occurs when a server will echo a request back via the Trace method, allowing an XSS
    attack to access to authorization headers and cookies inaccessible to JavaScript (such as cookies
    protected by HTTPOnly).  To mitigate this attack, browsers placed limits on <code>fetch()</code> and
    XMLHttpRequest; however some webservers have implemented non-standard headers such as <code>X-Http-Method-
    Override</code> that override the HTTP method, and made this attack possible again.  Firefox has applied
    the same mitigations to the use of this and similar headers. (CVE-2022-45411)

  - When resolving a symlink such as <code>file:///proc/self/fd/1</code>, an error message may be produced
    where the symlink was resolved to a string containing unitialized memory in the buffer.  This bug only
    affects Firefox on Unix-based operated systems (Android, Linux, MacOS). Windows is unaffected.
    (CVE-2022-45412)

  - Keyboard events reference strings like KeyA that were at fixed, known, and widely-spread addresses.
    Cache-based timing attacks such as Prime+Probe could have possibly figured out which keys were being
    pressed. (CVE-2022-45416)

  - If a custom mouse cursor is specified in CSS, under certain circumstances the cursor could have been drawn
    over the browser UI, resulting in potential user confusion or spoofing attacks. (CVE-2022-45418)

  - Use tables inside of an iframe, an attacker could have caused iframe contents to be rendered outside the
    boundaries of the iframe, resulting in potential user confusion or spoofing attacks. (CVE-2022-45420)

  - Mozilla developers Andrew McCreight and Gabriele Svelto reported memory safety bugs present in Firefox 106
    and Firefox ESR 102.4. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. (CVE-2022-45421)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-48/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 102.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45421");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'102.5', min:'102.0.0', severity:SECURITY_HOLE);
