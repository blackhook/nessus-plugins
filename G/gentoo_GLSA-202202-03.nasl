#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202202-03.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159007);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/24");

  script_cve_id(
    "CVE-2021-4129",
    "CVE-2021-4140",
    "CVE-2021-29970",
    "CVE-2021-29972",
    "CVE-2021-29974",
    "CVE-2021-29975",
    "CVE-2021-29976",
    "CVE-2021-29977",
    "CVE-2021-29980",
    "CVE-2021-29981",
    "CVE-2021-29982",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29987",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-29990",
    "CVE-2021-30547",
    "CVE-2021-38491",
    "CVE-2021-38493",
    "CVE-2021-38495",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43540",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546",
    "CVE-2022-0511",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22745",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751",
    "CVE-2022-22753",
    "CVE-2022-22754",
    "CVE-2022-22755",
    "CVE-2022-22756",
    "CVE-2022-22757",
    "CVE-2022-22758",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22762",
    "CVE-2022-22763",
    "CVE-2022-22764"
  );
  script_xref(name:"IAVA", value:"2021-A-0309-S");
  script_xref(name:"IAVA", value:"2021-A-0366-S");
  script_xref(name:"IAVA", value:"2021-A-0293-S");
  script_xref(name:"IAVA", value:"2021-A-0405");
  script_xref(name:"IAVA", value:"2021-A-0527-S");
  script_xref(name:"IAVA", value:"2022-A-0017-S");
  script_xref(name:"IAVA", value:"2021-A-0569-S");
  script_xref(name:"IAVA", value:"2022-A-0079-S");

  script_name(english:"GLSA-202202-03 : Mozilla Firefox: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202202-03 (Mozilla Firefox: Multiple vulnerabilities)

  - A malicious webpage could have triggered a use-after-free, memory corruption, and a potentially
    exploitable crash. *This bug could only be triggered when accessibility was enabled.*. This vulnerability
    affects Thunderbird < 78.12, Firefox ESR < 78.12, and Firefox < 90. (CVE-2021-29970)

  - A use-after-free vulnerability was found via testing, and traced to an out-of-date Cairo library. Updating
    the library resolved the issue, and may have remediated other, unknown security vulnerabilities as well.
    This vulnerability affects Firefox < 90. (CVE-2021-29972)

  - When network partitioning was enabled, e.g. as a result of Enhanced Tracking Protection settings, a TLS
    error page would allow the user to override an error on a domain which had specified HTTP Strict Transport
    Security (which implies that the error should not be override-able.) This issue did not affect the network
    connections, and they were correctly upgraded to HTTPS automatically. This vulnerability affects Firefox <
    90. (CVE-2021-29974)

  - Through a series of DOM manipulations, a message, over which the attacker had control of the text but not
    HTML or formatting, could be overlaid on top of another domain (with the new domain correctly shown in the
    address bar) resulting in possible user confusion. This vulnerability affects Firefox < 90.
    (CVE-2021-29975)

  - Mozilla developers reported memory safety bugs present in code shared between Firefox and Thunderbird.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.12,
    Firefox ESR < 78.12, and Firefox < 90. (CVE-2021-29976)

  - Mozilla developers reported memory safety bugs present in Firefox 89. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 90. (CVE-2021-29977)

  - Uninitialized memory in a canvas object could have caused an incorrect free() leading to memory corruption
    and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91,
    Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29980)

  - An issue present in lowering/register allocation could have led to obscure but deterministic register
    confusion failures in JITted code that would lead to a potentially exploitable crash. This vulnerability
    affects Firefox < 91 and Thunderbird < 91. (CVE-2021-29981)

  - Due to incorrect JIT optimization, we incorrectly interpreted data from the wrong type of object,
    resulting in the potential leak of a single bit of memory. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29982)

  - Instruction reordering resulted in a sequence of instructions that would cause an object to be incorrectly
    considered during garbage collection. This led to memory corruption and a potentially exploitable crash.
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29984)

  - A use-after-free vulnerability in media channels could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29985)

  - A suspected race condition when calling getaddrinfo led to memory corruption and a potentially exploitable
    crash. *Note: This issue only affected Linux operating systems. Other operating systems are unaffected.*
    This vulnerability affects Thunderbird < 78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91.
    (CVE-2021-29986)

  - After requesting multiple permissions, and closing the first permission panel, subsequent permission
    panels will be displayed in a different position but still record a click in the default location, making
    it possible to trick a user into accepting a permission they did not want to. *This bug only affects
    Firefox on Linux. Other operating systems are unaffected.*. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29987)

  - Firefox incorrectly treated an inline list-item element as a block element, resulting in an out of bounds
    read or memory corruption, and a potentially exploitable crash. This vulnerability affects Thunderbird <
    78.13, Thunderbird < 91, Firefox ESR < 78.13, and Firefox < 91. (CVE-2021-29988)

  - Mozilla developers reported memory safety bugs present in Firefox 90 and Firefox ESR 78.12. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.13, Firefox ESR < 78.13,
    and Firefox < 91. (CVE-2021-29989)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 90. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 91. (CVE-2021-29990)

  - Out of bounds write in ANGLE in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2021-30547)

  - Mixed-content checks were unable to analyze opaque origins which led to some mixed content being loaded.
    This vulnerability affects Firefox < 92. (CVE-2021-38491)

  - Mozilla developers reported memory safety bugs present in Firefox 91 and Firefox ESR 78.13. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.14, Thunderbird < 78.14,
    and Firefox < 92. (CVE-2021-38493)

  - Mozilla developers reported memory safety bugs present in Thunderbird 78.13.0. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Thunderbird < 91.1 and Firefox ESR < 91.1.
    (CVE-2021-38495)

  - The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass
    restrictions such as executing scripts or navigating the top-level frame. This vulnerability affects
    Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38503)

  - When interacting with an HTML input element's file picker dialog with webkitdirectory set, a use-after-
    free could have resulted, leading to memory corruption and a potentially exploitable crash. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38504)

  - Through a series of navigations, Firefox could have entered fullscreen mode without notification or
    warning to the user. This could lead to spoofing attacks on the browser UI including phishing. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38506)

  - The Opportunistic Encryption feature of HTTP2 (RFC 8164) allows a connection to be transparently upgraded
    to TLS while retaining the visual properties of an HTTP connection, including being same-origin with
    unencrypted connections on port 80. However, if a second encrypted port on the same IP address (e.g. port
    8443) did not opt-in to opportunistic encryption; a network attacker could forward a connection from the
    browser to port 443 to port 8443, causing the browser to treat the content of port 8443 as same-origin
    with HTTP. This was resolved by disabling the Opportunistic Encryption feature, which had low usage. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38507)

  - By displaying a form validity message in the correct location at the same time as a permission prompt
    (such as for geolocation), the validity message could have obscured the prompt, resulting in the user
    potentially being tricked into granting the permission. This vulnerability affects Firefox < 94,
    Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38508)

  - Due to an unusual sequence of attacker-controlled events, a Javascript alert() dialog with arbitrary
    (although unstyled) contents could be displayed over top an uncontrolled webpage of the attacker's
    choosing. This vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3.
    (CVE-2021-38509)

  - Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the
    target URL. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43536)

  - An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory
    leading to a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR <
    91.4.0, and Firefox < 95. (CVE-2021-43537)

  - By misusing a race in our notification code, an attacker could have forcefully hidden the notification for
    pages that had received full screen and pointer lock access, which could have been used for spoofing
    attacks. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43538)

  - Failure to correctly record the location of live pointers across wasm instance calls resulted in a GC
    occurring within the call not tracing those live pointers. This could have led to a use-after-free causing
    a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0,
    and Firefox < 95. (CVE-2021-43539)

  - WebExtensions with the correct permissions were able to create and install ServiceWorkers for third-party
    websites that would not have been uninstalled with the extension. This vulnerability affects Firefox < 95.
    (CVE-2021-43540)

  - When invoking protocol handlers for external protocols, a supplied parameter URL containing spaces was not
    properly escaped. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.
    (CVE-2021-43541)

  - Using XMLHttpRequest, an attacker could have identified installed applications by probing error messages
    for loading external protocols. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43542)

  - Documents loaded with the CSP sandbox directive could have escaped the sandbox's script restriction by
    embedding additional content. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and
    Firefox < 95. (CVE-2021-43543)

  - Using the Location API in a loop could have caused severe application hangs and crashes. This
    vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43545)

  - It was possible to recreate previous cursor spoofing attacks against users with a zoomed native cursor.
    This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95. (CVE-2021-43546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202202-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802768");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807947");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813498");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=821385");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=828538");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831039");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832992");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/firefox-91.6.0:esr
            
All Mozilla Firefox ESR binary users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/firefox-bin-91.6.0:esr
            
All Mozilla Firefox users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/firefox-97.0:rapid
            
All Mozilla Firefox binary users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/firefox-bin-97.0:rapid");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-client/firefox",
    'unaffected' : make_list("ge 91.6.0", "lt 92.0"),
    'vulnerable' : make_list("lt 91.6.0")
  },
  {
    'name' : "www-client/firefox",
    'unaffected' : make_list("lt 92.0", "ge 97.0"),
    'vulnerable' : make_list("ge 92.0")
  },
  {
    'name' : "www-client/firefox-bin",
    'unaffected' : make_list("ge 91.6.0", "lt 92.0"),
    'vulnerable' : make_list("lt 91.6.0")
  },
  {
    'name' : "www-client/firefox-bin",
    'unaffected' : make_list("lt 92.0", "ge 97.0"),
    'vulnerable' : make_list("ge 92.0")
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
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
