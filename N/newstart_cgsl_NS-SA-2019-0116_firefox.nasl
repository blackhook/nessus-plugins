#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0116. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127356);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-7753",
    "CVE-2017-7779",
    "CVE-2017-7784",
    "CVE-2017-7785",
    "CVE-2017-7786",
    "CVE-2017-7787",
    "CVE-2017-7791",
    "CVE-2017-7792",
    "CVE-2017-7793",
    "CVE-2017-7798",
    "CVE-2017-7800",
    "CVE-2017-7801",
    "CVE-2017-7802",
    "CVE-2017-7803",
    "CVE-2017-7807",
    "CVE-2017-7809",
    "CVE-2017-7810",
    "CVE-2017-7814",
    "CVE-2017-7818",
    "CVE-2017-7819",
    "CVE-2017-7823",
    "CVE-2017-7824",
    "CVE-2017-7826",
    "CVE-2017-7828",
    "CVE-2017-7830",
    "CVE-2017-7843"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : firefox Multiple Vulnerabilities (NS-SA-2019-0116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has firefox packages installed that are affected by multiple
vulnerabilities:

  - File downloads encoded with blob: and data: URL
    elements bypassed normal file download checks though the
    Phishing and Malware Protection feature and its block
    lists of suspicious sites and files. This would allow
    malicious sites to lure users into downloading
    executables that would otherwise be detected as
    suspicious. This vulnerability affects Firefox < 56,
    Firefox ESR < 52.4, and Thunderbird < 52.4.
    (CVE-2017-7814)

  - A use-after-free vulnerability can occur in design mode
    when image objects are resized if objects referenced
    during the resizing have been freed from memory. This
    results in a potentially exploitable crash. This
    vulnerability affects Firefox < 56, Firefox ESR < 52.4,
    and Thunderbird < 52.4. (CVE-2017-7819)

  - The content security policy (CSP) sandbox directive
    did not create a unique origin for the document, causing
    it to behave as if the allow-same-origin keyword were
    always specified. This could allow a Cross-Site
    Scripting (XSS) attack to be launched from unsafe
    content. This vulnerability affects Firefox < 56,
    Firefox ESR < 52.4, and Thunderbird < 52.4.
    (CVE-2017-7823)

  - A use-after-free vulnerability can occur when an editor
    DOM node is deleted prematurely during tree traversal
    while still bound to the document. This results in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.3, Firefox ESR < 52.3, and
    Firefox < 55. (CVE-2017-7809)

  - Memory safety bugs were reported in Firefox 54, Firefox
    ESR 52.2, and Thunderbird 52.2. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort that some of these could be exploited
    to run arbitrary code. This vulnerability affects
    Thunderbird < 52.3, Firefox ESR < 52.3, and Firefox <
    55. (CVE-2017-7779)

  - An out-of-bounds read occurs when applying style rules
    to pseudo-elements, such as ::first-line, using cached
    style data. This vulnerability affects Thunderbird <
    52.3, Firefox ESR < 52.3, and Firefox < 55.
    (CVE-2017-7753)

  - A buffer overflow can occur when manipulating Accessible
    Rich Internet Applications (ARIA) attributes within the
    DOM. This results in a potentially exploitable crash.
    This vulnerability affects Thunderbird < 52.3, Firefox
    ESR < 52.3, and Firefox < 55. (CVE-2017-7785)

  - A buffer overflow can occur when the image renderer
    attempts to paint non-displayable SVG elements. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.3, Firefox ESR <
    52.3, and Firefox < 55. (CVE-2017-7786)

  - Same-origin policy protections can be bypassed on pages
    with embedded iframes during page reloads, allowing the
    iframes to access content on the top level page, leading
    to information disclosure. This vulnerability affects
    Thunderbird < 52.3, Firefox ESR < 52.3, and Firefox <
    55. (CVE-2017-7787)

  - A buffer overflow will occur when viewing a certificate
    in the certificate manager if the certificate has an
    extremely long object identifier (OID). This results in
    a potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.3, Firefox ESR < 52.3, and
    Firefox < 55. (CVE-2017-7792)

  - On pages containing an iframe, the data: protocol can
    be used to create a modal alert that will render over
    arbitrary domains following page navigation, spoofing of
    the origin of the modal alert from the iframe content.
    This vulnerability affects Thunderbird < 52.3, Firefox
    ESR < 52.3, and Firefox < 55. (CVE-2017-7791)

  - A use-after-free vulnerability can occur in WebSockets
    when the object holding the connection is freed before
    the disconnection operation is finished. This results in
    an exploitable crash. This vulnerability affects
    Thunderbird < 52.3, Firefox ESR < 52.3, and Firefox <
    55. (CVE-2017-7800)

  - The Developer Tools feature suffers from a XUL injection
    vulnerability due to improper sanitization of the web
    page source code. In the worst case, this could allow
    arbitrary code execution when opening a malicious page
    with the style editor tool. This vulnerability affects
    Firefox ESR < 52.3 and Firefox < 55. (CVE-2017-7798)

  - A use-after-free vulnerability can occur when
    manipulating the DOM during the resize event of an image
    element. If these elements have been freed due to a lack
    of strong references, a potentially exploitable crash
    may occur when the freed elements are accessed. This
    vulnerability affects Thunderbird < 52.3, Firefox ESR <
    52.3, and Firefox < 55. (CVE-2017-7802)

  - A use-after-free vulnerability can occur while re-
    computing layout for a marquee element during window
    resizing where the updated style object is freed while
    still in use. This results in a potentially exploitable
    crash. This vulnerability affects Thunderbird < 52.3,
    Firefox ESR < 52.3, and Firefox < 55. (CVE-2017-7801)

  - A mechanism that uses AppCache to hijack a URL in a
    domain using fallback by serving the files from a sub-
    path on the domain. This has been addressed by requiring
    fallback files be inside the manifest directory. This
    vulnerability affects Thunderbird < 52.3, Firefox ESR <
    52.3, and Firefox < 55. (CVE-2017-7807)

  - When a page's content security policy (CSP) header
    contains a sandbox directive, other directives are
    ignored. This results in the incorrect enforcement of
    CSP. This vulnerability affects Thunderbird < 52.3,
    Firefox ESR < 52.3, and Firefox < 55. (CVE-2017-7803)

  - A use-after-free vulnerability can occur when reading an
    image observer during frame reconstruction after the
    observer has been freed. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.3, Firefox ESR < 52.3, and Firefox <
    55. (CVE-2017-7784)

  - A use-after-free vulnerability can occur when
    manipulating arrays of Accessible Rich Internet
    Applications (ARIA) elements within containers through
    the DOM. This results in a potentially exploitable
    crash. This vulnerability affects Firefox < 56, Firefox
    ESR < 52.4, and Thunderbird < 52.4. (CVE-2017-7818)

  - A buffer overflow occurs when drawing and validating
    elements with the ANGLE graphics library, used for WebGL
    content. This is due to an incorrect value being passed
    within the library during checks and results in a
    potentially exploitable crash. This vulnerability
    affects Firefox < 56, Firefox ESR < 52.4, and
    Thunderbird < 52.4. (CVE-2017-7824)

  - Memory safety bugs were reported in Firefox 55 and
    Firefox ESR 52.3. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Firefox < 56, Firefox
    ESR < 52.4, and Thunderbird < 52.4. (CVE-2017-7810)

  - A use-after-free vulnerability can occur in the Fetch
    API when the worker or the associated window are freed
    when still in use, resulting in a potentially
    exploitable crash. This vulnerability affects Firefox <
    56, Firefox ESR < 52.4, and Thunderbird < 52.4.
    (CVE-2017-7793)

  - A privacy flaw was discovered in Firefox. In Private
    Browsing mode, a web worker could write persistent data
    to IndexedDB, which was not cleared when exiting and
    would persist across multiple sessions. A malicious
    website could exploit the flaw to bypass private-
    browsing protections and uniquely fingerprint visitors.
    (CVE-2017-7843)

  - A use-after-free vulnerability can occur when flushing
    and resizing layout because the PressShell object has
    been freed while still in use. This results in a
    potentially exploitable crash during these operations.
    This vulnerability affects Firefox < 57, Firefox ESR <
    52.5, and Thunderbird < 52.5. (CVE-2017-7828)

  - Memory safety bugs were reported in Firefox 56 and
    Firefox ESR 52.4. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Firefox < 57, Firefox
    ESR < 52.5, and Thunderbird < 52.5. (CVE-2017-7826)

  - The Resource Timing API incorrectly revealed navigations
    in cross-origin iframes. This is a same-origin policy
    violation and could allow for data theft of URLs loaded
    by users. This vulnerability affects Firefox < 57,
    Firefox ESR < 52.5, and Thunderbird < 52.5.
    (CVE-2017-7830)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0116");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "firefox-52.5.1-1.el6.centos"
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
