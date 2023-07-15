#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0032. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127198);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-7762",
    "CVE-2017-16541",
    "CVE-2018-5148",
    "CVE-2018-5150",
    "CVE-2018-5154",
    "CVE-2018-5155",
    "CVE-2018-5156",
    "CVE-2018-5157",
    "CVE-2018-5158",
    "CVE-2018-5159",
    "CVE-2018-5168",
    "CVE-2018-5178",
    "CVE-2018-5183",
    "CVE-2018-5188",
    "CVE-2018-6126",
    "CVE-2018-12359",
    "CVE-2018-12360",
    "CVE-2018-12362",
    "CVE-2018-12363",
    "CVE-2018-12364",
    "CVE-2018-12365",
    "CVE-2018-12366",
    "CVE-2018-12376",
    "CVE-2018-12377",
    "CVE-2018-12378",
    "CVE-2018-12379",
    "CVE-2018-12383",
    "CVE-2018-12385",
    "CVE-2018-12386",
    "CVE-2018-12387",
    "CVE-2018-12389",
    "CVE-2018-12390",
    "CVE-2018-12392",
    "CVE-2018-12393",
    "CVE-2018-12395",
    "CVE-2018-12396",
    "CVE-2018-12397"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : firefox Multiple Vulnerabilities (NS-SA-2019-0032)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has firefox packages installed that are affected
by multiple vulnerabilities:

  - A buffer overflow can occur when rendering canvas
    content while adjusting the height and width of the
    canvas element dynamically, causing data to be written
    outside of the currently computed boundaries. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 60, Thunderbird <
    52.9, Firefox ESR < 60.1, Firefox ESR < 52.9, and
    Firefox < 61. (CVE-2018-12359)

  - A use-after-free vulnerability can occur when deleting
    an input element during a mutation event handler
    triggered by focusing that element. This results in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60, Thunderbird < 52.9, Firefox
    ESR < 60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-12360)

  - An integer overflow can occur during graphics operations
    done by the Supplemental Streaming SIMD Extensions 3
    (SSSE3) scaler, resulting in a potentially exploitable
    crash. This vulnerability affects Thunderbird < 60,
    Thunderbird < 52.9, Firefox ESR < 60.1, Firefox ESR <
    52.9, and Firefox < 61. (CVE-2018-12362)

  - A use-after-free vulnerability can occur when script
    uses mutation events to move DOM nodes between
    documents, resulting in the old document that held the
    node being freed but the node still having a pointer
    referencing it. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 60, Thunderbird < 52.9, Firefox ESR <
    60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-12363)

  - NPAPI plugins, such as Adobe Flash, can send non-simple
    cross-origin requests, bypassing CORS by making a same-
    origin POST that does a 307 redirect to the target site.
    This allows for a malicious site to engage in cross-site
    request forgery (CSRF) attacks. This vulnerability
    affects Thunderbird < 60, Thunderbird < 52.9, Firefox
    ESR < 60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-12364)

  - A compromised IPC child process can escape the content
    sandbox and list the names of arbitrary files on the
    file system without user consent or interaction. This
    could result in exposure of private local files. This
    vulnerability affects Thunderbird < 60, Thunderbird <
    52.9, Firefox ESR < 60.1, Firefox ESR < 52.9, and
    Firefox < 61. (CVE-2018-12365)

  - An invalid grid size during QCMS (color profile)
    transformations can result in the out-of-bounds read
    interpreted as a float value. This could leak private
    data into the output. This vulnerability affects
    Thunderbird < 60, Thunderbird < 52.9, Firefox ESR <
    60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-12366)

  - A vulnerability can occur when capturing a media stream
    when the media source type is changed as the capture is
    occurring. This can result in stream data being cast to
    the wrong type causing a potentially exploitable crash.
    This vulnerability affects Thunderbird < 60, Firefox ESR
    < 60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-5156)

  - Memory safety bugs present in Firefox 60, Firefox ESR
    60, and Firefox ESR 52.8. Some of these bugs showed
    evidence of memory corruption and we presume that with
    enough effort that some of these could be exploited to
    run arbitrary code. This vulnerability affects
    Thunderbird < 60, Thunderbird < 52.9, Firefox ESR <
    60.1, Firefox ESR < 52.9, and Firefox < 61.
    (CVE-2018-5188)

  - A precision error in Skia in Google Chrome prior to
    67.0.3396.62 allowed a remote attacker to perform an out
    of bounds memory write via a crafted HTML page.
    (CVE-2018-6126)

  - A use-after-free vulnerability can occur while
    enumerating attributes during SVG animations with clip
    paths. This results in a potentially exploitable crash.
    This vulnerability affects Thunderbird < 52.8,
    Thunderbird ESR < 52.8, Firefox < 60, and Firefox ESR <
    52.8. (CVE-2018-5154)

  - A use-after-free vulnerability can occur while adjusting
    layout during SVG animations with text paths. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.8, Thunderbird
    ESR < 52.8, Firefox < 60, and Firefox ESR < 52.8.
    (CVE-2018-5155)

  - Same-origin protections for the PDF viewer can be
    bypassed, allowing a malicious site to intercept
    messages meant for the viewer. This could allow the site
    to retrieve PDF files restricted to viewing by an
    authenticated user on a third-party website. This
    vulnerability affects Firefox ESR < 52.8 and Firefox <
    60. (CVE-2018-5157)

  - The PDF viewer does not sufficiently sanitize PostScript
    calculator functions, allowing malicious JavaScript to
    be injected through a crafted PDF file. This JavaScript
    can then be run with the permissions of the PDF viewer
    by its worker. This vulnerability affects Firefox ESR <
    52.8 and Firefox < 60. (CVE-2018-5158)

  - An integer overflow can occur in the Skia library due to
    32-bit integer use in an array without integer overflow
    checks, resulting in possible out-of-bounds writes. This
    could lead to a potentially exploitable crash
    triggerable by web content. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5159)

  - A buffer overflow was found during UTF8 to Unicode
    string conversion within JavaScript with extremely large
    amounts of data. This vulnerability requires the use of
    a malicious or vulnerable legacy extension in order to
    occur. This vulnerability affects Thunderbird ESR <
    52.8, Thunderbird < 52.8, and Firefox ESR < 52.8.
    (CVE-2018-5178)

  - Mozilla developers backported selected changes in the
    Skia library. These changes correct memory corruption
    issues including invalid buffer reads and writes during
    graphic operations. This vulnerability affects
    Thunderbird ESR < 52.8, Thunderbird < 52.8, and Firefox
    ESR < 52.8. (CVE-2018-5183)

  - A use-after-free vulnerability can occur in the
    compositor during certain graphics operations when a raw
    pointer is used instead of a reference counted one. This
    results in a potentially exploitable crash. This
    vulnerability affects Firefox ESR < 52.7.3 and Firefox <
    59.0.2. (CVE-2018-5148)

  - When entered directly, Reader Mode did not strip the
    username and password section of URLs displayed in the
    addressbar. This can be used for spoofing the domain of
    the current page. This vulnerability affects Firefox <
    54. (CVE-2017-7762)

  - Memory safety bugs present in Firefox 61 and Firefox ESR
    60.1. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort that
    some of these could be exploited to run arbitrary code.
    This vulnerability affects Firefox < 62, Firefox ESR <
    60.2, and Thunderbird < 60.2.1. (CVE-2018-12376)

  - A use-after-free vulnerability can occur when refresh
    driver timers are refreshed in some circumstances during
    shutdown when the timer is deleted while still in use.
    This results in a potentially exploitable crash. This
    vulnerability affects Firefox < 62, Firefox ESR < 60.2,
    and Thunderbird < 60.2.1. (CVE-2018-12377)

  - A use-after-free vulnerability can occur when an
    IndexedDB index is deleted while still in use by
    JavaScript code that is providing payload values to be
    stored. This results in a potentially exploitable crash.
    This vulnerability affects Firefox < 62, Firefox ESR <
    60.2, and Thunderbird < 60.2.1. (CVE-2018-12378)

  - When the Mozilla Updater opens a MAR format file which
    contains a very long item filename, an out-of-bounds
    write can be triggered, leading to a potentially
    exploitable crash. This requires running the Mozilla
    Updater manually on the local system with the malicious
    MAR file in order to occur. This vulnerability affects
    Firefox < 62, Firefox ESR < 60.2, and Thunderbird <
    60.2.1. (CVE-2018-12379)

  - If a user saved passwords before Firefox 58 and then
    later set a master password, an unencrypted copy of
    these passwords is still accessible. This is because the
    older stored password file was not deleted when the data
    was copied to a new format starting in Firefox 58. The
    new master password is added only on the new file. This
    could allow the exposure of stored password data outside
    of user expectations. This vulnerability affects Firefox
    < 62, Firefox ESR < 60.2.1, and Thunderbird < 60.2.1.
    (CVE-2018-12383)

  - A vulnerability in register allocation in JavaScript can
    lead to type confusion, allowing for an arbitrary read
    and write. This leads to remote code execution inside
    the sandboxed content process when triggered. This
    vulnerability affects Firefox ESR < 60.2.2 and Firefox <
    62.0.3. (CVE-2018-12386)

  - A vulnerability where the JavaScript JIT compiler
    inlines Array.prototype.push with multiple arguments
    that results in the stack pointer being off by 8 bytes
    after a bailout. This leaks a memory address to the
    calling function which can be used as part of an exploit
    inside the sandboxed content process. This vulnerability
    affects Firefox ESR < 60.2.2 and Firefox < 62.0.3.
    (CVE-2018-12387)

  - Firefox proxy settings can be bypassed by using the
    automount feature with autofs to create a mount point on
    the local file system. Content can be loaded from this
    mounted file system directly using a `file:` URI,
    bypassing configured proxy settings. This issue only
    affects OS X in default configuration; on Linux systems,
    autofs must also be installed for the vulnerability to
    occur. (CVE-2017-16541)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox ESR 60.2. Some of these
    bugs showed evidence of memory corruption and we presume
    that with enough effort that some of these could be
    exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 60.3 and Thunderbird < 60.3.
    (CVE-2018-12389)

  - When manipulating user events in nested loops while
    opening a document through script, it is possible to
    trigger a potentially exploitable crash due to poor
    event handling. This vulnerability affects Firefox < 63,
    Firefox ESR < 60.3, and Thunderbird < 60.3.
    (CVE-2018-12392)

  - By rewriting the Host: request headers using the
    webRequest API, a WebExtension can bypass domain
    restrictions through domain fronting. This would allow
    access to domains that share a host that are otherwise
    restricted. This vulnerability affects Firefox ESR <
    60.3 and Firefox < 63. (CVE-2018-12395)

  - A vulnerability where a WebExtension can run content
    scripts in disallowed contexts following navigation or
    other events. This allows for potential privilege
    escalation by the WebExtension on sites where content
    scripts should not be run. This vulnerability affects
    Firefox ESR < 60.3 and Firefox < 63. (CVE-2018-12396)

  - A WebExtension can request access to local files without
    the warning prompt stating that the extension will
    Access your data for all websites being displayed to
    the user. This allows extensions to run content scripts
    in local pages without permission warnings when a local
    file is opened. This vulnerability affects Firefox ESR <
    60.3 and Firefox < 63. (CVE-2018-12397)

  - A potentially exploitable crash in TransportSecurityInfo
    used for SSL can be triggered by data stored in the
    local cache in the user profile directory. This issue is
    only exploitable in combination with another
    vulnerability allowing an attacker to write data into
    the local cache or from locally installed malware. This
    issue also triggers a non-exploitable startup crash for
    users switching between the Nightly and Release versions
    of Firefox if the same profile is used. This
    vulnerability affects Thunderbird < 60.2.1, Firefox ESR
    < 60.2.1, and Firefox < 62.0.2. (CVE-2018-12385)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 62 and Firefox ESR 60.2.
    Some of these bugs showed evidence of memory corruption
    and we presume that with enough effort that some of
    these could be exploited to run arbitrary code. This
    vulnerability affects Firefox < 63, Firefox ESR < 60.3,
    and Thunderbird < 60.3. (CVE-2018-12390)

  - A potential vulnerability was found in 32-bit builds
    where an integer overflow during the conversion of
    scripts to an internal UTF-16 representation could
    result in allocating a buffer too small for the
    conversion. This leads to a possible out-of-bounds
    write. *Note: 64-bit builds are not vulnerable to this
    issue.*. This vulnerability affects Firefox < 63,
    Firefox ESR < 60.3, and Thunderbird < 60.3.
    (CVE-2018-12393)

  - Memory safety bugs were reported in Firefox 59, Firefox
    ESR 52.7, and Thunderbird 52.7. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort that some of these could be exploited
    to run arbitrary code. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5150)

  - Sites can bypass security checks on permissions to
    install lightweight themes by manipulating the baseURI
    property of the theme element. This could allow a
    malicious site to install a theme without user
    interaction which could contain offensive or
    embarrassing images. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5168)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0032");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5188");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "firefox-60.3.0-1.el7.centos",
    "firefox-debuginfo-60.3.0-1.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "firefox-60.3.0-1.el7.centos",
    "firefox-debuginfo-60.3.0-1.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
