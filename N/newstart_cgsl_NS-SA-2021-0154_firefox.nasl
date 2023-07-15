#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0154. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154543);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-12422",
    "CVE-2020-12424",
    "CVE-2020-12425",
    "CVE-2020-15648",
    "CVE-2020-15653",
    "CVE-2020-15654",
    "CVE-2020-15656",
    "CVE-2020-15658",
    "CVE-2020-15673",
    "CVE-2020-15676",
    "CVE-2020-15677",
    "CVE-2020-15678",
    "CVE-2020-15683",
    "CVE-2020-15969",
    "CVE-2020-16012",
    "CVE-2020-16042",
    "CVE-2020-26950",
    "CVE-2020-26951",
    "CVE-2020-26953",
    "CVE-2020-26956",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26965",
    "CVE-2020-26968",
    "CVE-2020-26971",
    "CVE-2020-26973",
    "CVE-2020-26974",
    "CVE-2020-26978",
    "CVE-2020-35111",
    "CVE-2020-35113"
  );
  script_xref(name:"IAVA", value:"2020-A-0287-S");
  script_xref(name:"IAVA", value:"2020-A-0344-S");
  script_xref(name:"IAVA", value:"2020-A-0435-S");
  script_xref(name:"IAVA", value:"2020-A-0472-S");
  script_xref(name:"IAVA", value:"2020-A-0443-S");
  script_xref(name:"IAVA", value:"2020-A-0486-S");
  script_xref(name:"IAVA", value:"2020-A-0537-S");
  script_xref(name:"IAVA", value:"2020-A-0533-S");
  script_xref(name:"IAVA", value:"2020-A-0571-S");
  script_xref(name:"IAVA", value:"2020-A-0531-S");
  script_xref(name:"IAVA", value:"2020-A-0575-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : firefox Multiple Vulnerabilities (NS-SA-2021-0154)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has firefox packages installed that are affected
by multiple vulnerabilities:

  - In non-standard configurations, a JPEG image created by JavaScript could have caused an internal variable
    to overflow, resulting in an out of bounds write, memory corruption, and a potentially exploitable crash.
    This vulnerability affects Firefox < 78. (CVE-2020-12422)

  - When constructing a permission prompt for WebRTC, a URI was supplied from the content process. This URI
    was untrusted, and could have been the URI of an origin that was previously granted permission; bypassing
    the prompt. This vulnerability affects Firefox < 78. (CVE-2020-12424)

  - Due to confusion processing a hyphen character in Date.parse(), a one-byte out of bounds read could have
    occurred, leading to potential information disclosure. This vulnerability affects Firefox < 78.
    (CVE-2020-12425)

  - Using object or embed tags, it was possible to frame other websites, even if they disallowed framing using
    the X-Frame-Options header. This vulnerability affects Thunderbird < 78 and Firefox < 78.0.2.
    (CVE-2020-15648)

  - An iframe sandbox element with the allow-popups flag could be bypassed when using noopener links. This
    could have led to security issues for websites relying on sandbox configurations that allowed popups and
    hosted arbitrary content. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird <
    78.1. (CVE-2020-15653)

  - When in an endless loop, a website specifying a custom cursor using CSS could make it look like the user
    is interacting with the user interface, when they are not. This could lead to a perceived broken state,
    especially when interactions with existing browser dialogs and warnings do not work. This vulnerability
    affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1. (CVE-2020-15654)

  - JIT optimizations involving the Javascript arguments object could confuse later optimizations. This risk
    was already mitigated by various precautions in the code, resulting in this bug rated at only moderate
    severity. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1.
    (CVE-2020-15656)

  - The code for downloading files did not properly take care of special characters, which led to an attacker
    being able to cut off the file ending at an earlier position, leading to a different file type being
    downloaded than shown in the dialog. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and
    Thunderbird < 78.1. (CVE-2020-15658)

  - Mozilla developers reported memory safety bugs present in Firefox 80 and Firefox ESR 78.2. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 81, Thunderbird < 78.3, and
    Firefox ESR < 78.3. (CVE-2020-15673)

  - Firefox sometimes ran the onload handler for SVG elements that the DOM sanitizer decided to remove,
    resulting in JavaScript being executed after pasting attacker-controlled data into a contenteditable
    element. This vulnerability affects Firefox < 81, Thunderbird < 78.3, and Firefox ESR < 78.3.
    (CVE-2020-15676)

  - By exploiting an Open Redirect vulnerability on a website, an attacker could have spoofed the site
    displayed in the download file dialog to show the original site (the one suffering from the open redirect)
    rather than the site the file was actually downloaded from. This vulnerability affects Firefox < 81,
    Thunderbird < 78.3, and Firefox ESR < 78.3. (CVE-2020-15677)

  - When recursing through graphical layers while scrolling, an iterator may have become invalid, resulting in
    a potential use-after-free. This occurs because the function
    APZCTreeManager::ComputeClippedCompositionBounds did not follow iterator invalidation rules. This
    vulnerability affects Firefox < 81, Thunderbird < 78.3, and Firefox ESR < 78.3. (CVE-2020-15678)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 81 and Firefox ESR
    78.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.4,
    Firefox < 82, and Thunderbird < 78.4. (CVE-2020-15683)

  - Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15969)

  - Side-channel information leakage in graphics in Google Chrome prior to 87.0.4280.66 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-16012)

  - Uninitialized Use in V8 in Google Chrome prior to 87.0.4280.88 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-16042)

  - In certain circumstances, the MCallGetProperty opcode can be emitted with unmet assumptions resulting in
    an exploitable use-after-free condition. This vulnerability affects Firefox < 82.0.3, Firefox ESR <
    78.4.1, and Thunderbird < 78.4.2. (CVE-2020-26950)

  - A parsing and event loading mismatch in Firefox's SVG code could have allowed load events to fire, even
    after sanitization. An attacker already capable of exploiting an XSS vulnerability in privileged internal
    pages could have used this attack to bypass our built-in sanitizer. This vulnerability affects Firefox <
    83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26951)

  - It was possible to cause the browser to enter fullscreen mode without displaying the security UI; thus
    making it possible to attempt a phishing attack or otherwise confuse the user. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26953)

  - In some cases, removing HTML elements during sanitization would keep existing SVG event handlers and
    therefore lead to XSS. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird <
    78.5. (CVE-2020-26956)

  - Firefox did not block execution of scripts with incorrect MIME types when the response was intercepted and
    cached through a ServiceWorker. This could lead to a cross-site script inclusion vulnerability, or a
    Content Security Policy bypass. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and
    Thunderbird < 78.5. (CVE-2020-26958)

  - During browser shutdown, reference decrementing could have occured on a previously freed object, resulting
    in a use-after-free, memory corruption, and a potentially exploitable crash. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26959)

  - If the Compact() method was called on an nsTArray, the array could have been reallocated without updating
    other pointers, leading to a potential use-after-free and exploitable crash. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26960)

  - When DNS over HTTPS is in use, it intentionally filters RFC1918 and related IP ranges from the responses
    as these do not make sense coming from a DoH resolver. However when an IPv4 address was mapped through
    IPv6, these addresses were erroneously let through, leading to a potential DNS Rebinding attack. This
    vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26961)

  - Some websites have a feature Show Password where clicking a button will change a password field into a
    textbook field, revealing the typed password. If, when using a software keyboard that remembers user
    input, a user typed their password and used that feature, the type of the password field was changed,
    resulting in a keyboard layout change and the possibility for the software keyboard to remember the typed
    password. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5.
    (CVE-2020-26965)

  - Mozilla developers reported memory safety bugs present in Firefox 82 and Firefox ESR 78.4. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and
    Thunderbird < 78.5. (CVE-2020-26968)

  - Certain blit values provided by the user were not properly constrained leading to a heap buffer overflow
    on some video drivers. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR <
    78.6. (CVE-2020-26971)

  - Certain input to the CSS Sanitizer confused it, resulting in incorrect components being removed. This
    could have been used as a sanitizer bypass. This vulnerability affects Firefox < 84, Thunderbird < 78.6,
    and Firefox ESR < 78.6. (CVE-2020-26973)

  - When flex-basis was used on a table wrapper, a StyleGenericFlexBasis object could have been incorrectly
    cast to the wrong type. This resulted in a heap user-after-free, memory corruption, and a potentially
    exploitable crash. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR < 78.6.
    (CVE-2020-26974)

  - Using techniques that built on the slipstream research, a malicious webpage could have exposed both an
    internal network's hosts as well as services running on the user's local machine. This vulnerability
    affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR < 78.6. (CVE-2020-26978)

  - When an extension with the proxy permission registered to receive <all_urls>, the proxy.onRequest callback
    was not triggered for view-source URLs. While web content cannot navigate to such URLs, a user opening
    View Source could have inadvertently leaked their IP address. This vulnerability affects Firefox < 84,
    Thunderbird < 78.6, and Firefox ESR < 78.6. (CVE-2020-35111)

  - Mozilla developers reported memory safety bugs present in Firefox 83 and Firefox ESR 78.5. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and
    Firefox ESR < 78.6. (CVE-2020-35113)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0154");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12422");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12424");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12425");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15648");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15653");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15654");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15656");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15658");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15673");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15676");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15677");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15678");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15683");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15969");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16012");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-16042");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26950");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26951");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26953");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26956");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26958");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26959");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26960");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26961");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26965");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26968");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26971");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26973");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26974");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-26978");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-35111");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-35113");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15683");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox MCallGetProperty Write Side Effects Use After Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'firefox-78.6.0-1.el7.centos'
  ],
  'CGSL MAIN 5.05': [
    'firefox-78.6.0-1.el7.centos'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
