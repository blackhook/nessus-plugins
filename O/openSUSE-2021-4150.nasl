#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:4150-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156271);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id(
    "CVE-2021-29981",
    "CVE-2021-29982",
    "CVE-2021-29987",
    "CVE-2021-29991",
    "CVE-2021-32810",
    "CVE-2021-38492",
    "CVE-2021-38493",
    "CVE-2021-38495",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501",
    "CVE-2021-38502",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38505",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-38510",
    "CVE-2021-40529",
    "CVE-2021-43528",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546"
  );
  script_xref(name:"IAVA", value:"2021-A-0366-S");
  script_xref(name:"IAVA", value:"2021-A-0386-S");
  script_xref(name:"IAVA", value:"2021-A-0461-S");
  script_xref(name:"IAVA", value:"2021-A-0405");
  script_xref(name:"IAVA", value:"2021-A-0527-S");
  script_xref(name:"IAVA", value:"2021-A-0569-S");
  script_xref(name:"IAVA", value:"2021-A-0450-S");

  script_name(english:"openSUSE 15 Security Update : MozillaThunderbird (openSUSE-SU-2021:4150-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:4150-1 advisory.

  - An issue present in lowering/register allocation could have led to obscure but deterministic register
    confusion failures in JITted code that would lead to a potentially exploitable crash. This vulnerability
    affects Firefox < 91 and Thunderbird < 91. (CVE-2021-29981)

  - Due to incorrect JIT optimization, we incorrectly interpreted data from the wrong type of object,
    resulting in the potential leak of a single bit of memory. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29982)

  - After requesting multiple permissions, and closing the first permission panel, subsequent permission
    panels will be displayed in a different position but still record a click in the default location, making
    it possible to trick a user into accepting a permission they did not want to. *This bug only affects
    Firefox on Linux. Other operating systems are unaffected.*. This vulnerability affects Firefox < 91 and
    Thunderbird < 91. (CVE-2021-29987)

  - Firefox incorrectly accepted a newline in a HTTP/3 header, interpretting it as two separate headers. This
    allowed for a header splitting attack against servers using HTTP/3. This vulnerability affects Firefox <
    91.0.1 and Thunderbird < 91.0.1. (CVE-2021-29991)

  - crossbeam-deque is a package of work-stealing deques for building task schedulers when programming in
    Rust. In versions prior to 0.7.4 and 0.8.0, the result of the race condition is that one or more tasks in
    the worker queue can be popped twice instead of other tasks that are forgotten and never popped. If tasks
    are allocated on the heap, this can cause double free and a memory leak. If not, this still can cause a
    logical bug. Crates using `Stealer::steal`, `Stealer::steal_batch`, or `Stealer::steal_batch_and_pop` are
    affected by this issue. This has been fixed in crossbeam-deque 0.8.1 and 0.7.4. (CVE-2021-32810)

  - When delegating navigations to the operating system, Firefox would accept the `mk` scheme which might
    allow attackers to launch pages and execute scripts in Internet Explorer in unprivileged mode. *This bug
    only affects Firefox for Windows. Other operating systems are unaffected.*. This vulnerability affects
    Firefox < 92, Thunderbird < 91.1, Thunderbird < 78.14, Firefox ESR < 78.14, and Firefox ESR < 91.1.
    (CVE-2021-38492)

  - Mozilla developers reported memory safety bugs present in Firefox 91 and Firefox ESR 78.13. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 78.14, Thunderbird < 78.14,
    and Firefox < 92. (CVE-2021-38493)

  - Mozilla developers reported memory safety bugs present in Thunderbird 78.13.0. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Thunderbird < 91.1 and Firefox ESR < 91.1.
    (CVE-2021-38495)

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.15,
    Thunderbird < 91.2, Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38496)

  - Through use of reportValidity() and window.open(), a plain-text validation message could have been
    overlaid on another origin, leading to possible user confusion and spoofing attacks. This vulnerability
    affects Firefox < 93, Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38497)

  - During process shutdown, a document could have caused a use-after-free of a languages service object,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox < 93,
    Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38498)

  - Mozilla developers reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.15, Thunderbird < 91.2,
    Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38500)

  - Mozilla developers reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 93, Thunderbird < 91.2, and
    Firefox ESR < 91.2. (CVE-2021-38501)

  - Thunderbird ignored the configuration to require STARTTLS security for an SMTP connection. A MITM could
    perform a downgrade attack to intercept transmitted messages, or could take control of the authenticated
    session to execute SMTP commands chosen by the MITM. If an unprotected authentication method was
    configured, the MITM could obtain the authentication credentials, too. This vulnerability affects
    Thunderbird < 91.2. (CVE-2021-38502)

  - The iframe sandbox rules were not correctly applied to XSLT stylesheets, allowing an iframe to bypass
    restrictions such as executing scripts or navigating the top-level frame. This vulnerability affects
    Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38503)

  - When interacting with an HTML input element's file picker dialog with webkitdirectory set, a use-after-
    free could have resulted, leading to memory corruption and a potentially exploitable crash. This
    vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38504)

  - Microsoft introduced a new feature in Windows 10 known as Cloud Clipboard which, if enabled, will record
    data copied to the clipboard to the cloud, and make it available on other computers in certain scenarios.
    Applications that wish to prevent copied data from being recorded in Cloud History must use specific
    clipboard formats; and Firefox before versions 94 and ESR 91.3 did not implement them. This could have
    caused sensitive data to be recorded to a user's Microsoft account. *This bug only affects Firefox for
    Windows 10+ with Cloud Clipboard enabled. Other operating systems are unaffected.*. This vulnerability
    affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3. (CVE-2021-38505)

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

  - The executable file warning was not presented when downloading .inetloc files, which, due to a flaw in Mac
    OS, can run commands on a user's computer.*Note: This issue only affected Mac OS operating systems. Other
    operating systems are unaffected.*. This vulnerability affects Firefox < 94, Thunderbird < 91.3, and
    Firefox ESR < 91.3. (CVE-2021-38510)

  - The ElGamal implementation in Botan through 2.18.1, as used in Thunderbird and other products, allows
    plaintext recovery because, during interaction between two cryptographic libraries, a certain dangerous
    combination of the prime defined by the receiver's public key, the generator defined by the receiver's
    public key, and the sender's ephemeral exponents can lead to a cross-configuration attack against OpenPGP.
    (CVE-2021-40529)

  - Thunderbird unexpectedly enabled JavaScript in the composition area. The JavaScript execution context was
    limited to this area and did not receive chrome-level privileges, but could be used as a stepping stone to
    further an attack with other vulnerabilities. This vulnerability affects Thunderbird < 91.4.0.
    (CVE-2021-43528)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193485");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OQOGFW6JISWI3PQR7AHD3OEX3SPELMFB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfbe5c04");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-40529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43546");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'MozillaThunderbird-91.4.0-8.45.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaThunderbird-translations-common-91.4.0-8.45.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'MozillaThunderbird-translations-other-91.4.0-8.45.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
