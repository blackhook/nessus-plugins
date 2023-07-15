##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4756-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147994);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-23968",
    "CVE-2021-23969",
    "CVE-2021-23970",
    "CVE-2021-23971",
    "CVE-2021-23972",
    "CVE-2021-23973",
    "CVE-2021-23974",
    "CVE-2021-23975",
    "CVE-2021-23978",
    "CVE-2021-23979"
  );
  script_xref(name:"USN", value:"4756-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Firefox vulnerabilities (USN-4756-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4756-1 advisory.

  - If Content Security Policy blocked frame navigation, the full destination of a redirect served in the
    frame was reported in the violation report; as opposed to the original frame URI. This could be used to
    leak sensitive information contained in such URIs. This vulnerability affects Firefox < 86, Thunderbird <
    78.8, and Firefox ESR < 78.8. (CVE-2021-23968)

  - As specified in the W3C Content Security Policy draft, when creating a violation report, User agents need
    to ensure that the source file is the URL requested by the page, pre-redirects. If thats not possible,
    user agents need to strip the URL down to an origin to avoid unintentional leakage. Under certain types
    of redirects, Firefox incorrectly set the source file to be the destination of the redirects. This was
    fixed to be the redirect destination's origin. This vulnerability affects Firefox < 86, Thunderbird <
    78.8, and Firefox ESR < 78.8. (CVE-2021-23969)

  - Context-specific code was included in a shared jump table; resulting in assertions being triggered in
    multithreaded wasm code. This vulnerability affects Firefox < 86. (CVE-2021-23970)

  - When processing a redirect with a conflicting Referrer-Policy, Firefox would have adopted the redirect's
    Referrer-Policy. This would have potentially resulted in more information than intended by the original
    origin being provided to the destination of the redirect. This vulnerability affects Firefox < 86.
    (CVE-2021-23971)

  - One phishing tactic on the web is to provide a link with HTTP Auth. For example
    'https://www.phishingtarget.com@evil.com'. To mitigate this type of attack, Firefox will display a warning
    dialog; however, this warning dialog would not have been displayed if evil.com used a redirect that was
    cached by the browser. This vulnerability affects Firefox < 86. (CVE-2021-23972)

  - When trying to load a cross-origin resource in an audio/video context a decoding error may have resulted,
    and the content of that error may have revealed information about the resource. This vulnerability affects
    Firefox < 86, Thunderbird < 78.8, and Firefox ESR < 78.8. (CVE-2021-23973)

  - The DOMParser API did not properly process '' elements for escaping. This could be used as an
    mXSS vector to bypass an HTML Sanitizer. This vulnerability affects Firefox < 86. (CVE-2021-23974)

  - The developer page about:memory has a Measure function for exploring what object types the browser has
    allocated and their sizes. When this function was invoked we incorrectly called the sizeof function,
    instead of using the API method that checks for invalid pointers. This vulnerability affects Firefox < 86.
    (CVE-2021-23975)

  - Mozilla developers reported memory safety bugs present in Firefox 85 and Firefox ESR 78.7. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 86, Thunderbird < 78.8, and
    Firefox ESR < 78.8. (CVE-2021-23978)

  - Mozilla developers reported memory safety bugs present in Firefox 85. Some of these bugs showed evidence
    of memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 86. (CVE-2021-23979)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4756-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-geckodriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zh-hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-mozsymbols");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'firefox', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-dev', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-af', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-an', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-as', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-az', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-be', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-br', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-da', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-de', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-el', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-en', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-es', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-et', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-he', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-id', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-is', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-it', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-km', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-my', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-or', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-si', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-te', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-th', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '86.0+build3-0ubuntu0.16.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-dev', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-af', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-an', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-as', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-az', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-be', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-br', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-da', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-de', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-el', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-en', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-es', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-et', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-he', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-id', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-is', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-it', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-km', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-my', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-or', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-si', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-te', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-th', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '86.0+build3-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '86.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'firefox', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-dev', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-geckodriver', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-af', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-an', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ar', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-as', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ast', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-az', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-be', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-bg', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-bn', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-br', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-bs', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ca', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-cak', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-cs', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-csb', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-cy', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-da', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-de', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-el', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-en', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-eo', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-es', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-et', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-eu', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-fa', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-fi', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-fr', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-fy', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ga', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-gd', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-gl', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-gn', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-gu', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-he', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-hi', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-hr', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-hsb', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-hu', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-hy', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ia', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-id', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-is', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-it', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ja', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ka', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-kab', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-kk', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-km', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-kn', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ko', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ku', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-lg', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-lt', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-lv', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-mai', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-mk', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ml', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-mn', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-mr', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ms', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-my', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-nb', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ne', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-nl', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-nn', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-nso', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-oc', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-or', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-pa', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-pl', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-pt', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ro', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ru', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-si', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sk', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sl', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sq', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sr', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sv', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-sw', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ta', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-te', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-th', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-tr', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-uk', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-ur', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-uz', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-vi', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-xh', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-locale-zu', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'firefox-mozsymbols', 'pkgver': '86.0+build3-0ubuntu0.20.10.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-geckodriver / firefox-locale-af / etc');
}