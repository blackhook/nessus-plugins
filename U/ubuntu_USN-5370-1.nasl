#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5370-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159593);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-1097",
    "CVE-2022-24713",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28283",
    "CVE-2022-28284",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28287",
    "CVE-2022-28288",
    "CVE-2022-28289"
  );
  script_xref(name:"USN", value:"5370-1");
  script_xref(name:"IAVA", value:"2022-A-0134-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Firefox vulnerabilities (USN-5370-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5370-1 advisory.

  - regex is an implementation of regular expressions for the Rust language. The regex crate features built-in
    mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched
    by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This
    guarantee is documented and it's considered part of the crate's API. Unfortunately a bug was discovered in
    the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing,
    and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial
    of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted
    regexes. All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is
    include starting from regex 1.5.5. All users accepting user-controlled regexes are recommended to upgrade
    immediately to the latest version of the regex crate. Unfortunately there is no fixed set of problematic
    regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability.
    Because of this, it us not recommend to deny known problematic regexes. (CVE-2022-24713)

  - <code>NSSToken</code> objects were referenced via direct points, and could have been accessed in an unsafe
    way on different threads, leading to a use-after-free and potentially exploitable crash. This
    vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox ESR < 91.8. (CVE-2022-1097)

  - If a compromised content process sent an unexpected number of WebAuthN Extensions in a Register command to
    the parent process, an out of bounds write would have occurred leading to memory corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and Firefox
    ESR < 91.8. (CVE-2022-28281)

  - By using a link with <code>rel=localization</code> a use-after-free could have been triggered by
    destroying an object during JavaScript execution and then referencing the object through a freed pointer,
    leading to a potential exploitable crash. This vulnerability affects Thunderbird < 91.8, Firefox < 99, and
    Firefox ESR < 91.8. (CVE-2022-28282)

  - The sourceMapURL feature in devtools was missing security checks that would have allowed a webpage to
    attempt to include local files or other files that should have been inaccessible. This vulnerability
    affects Firefox < 99. (CVE-2022-28283)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5370-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24713");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28289");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-szl");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'firefox', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-dev', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-af', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-an', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-as', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-az', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-be', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-br', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-da', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-de', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-el', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-en', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-es', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-et', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-he', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-id', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-is', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-it', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-km', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-my', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-or', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-si', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-te', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-th', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '99.0+build2-0ubuntu0.18.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '99.0+build2-0ubuntu0.20.04.2'},
    {'osver': '21.10', 'pkgname': 'firefox', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-dev', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-geckodriver', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-af', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-an', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ar', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-as', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ast', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-az', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-be', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bg', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bn', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-br', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bs', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ca', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cak', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cs', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-csb', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cy', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-da', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-de', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-el', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-en', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-eo', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-es', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-et', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-eu', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fa', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fi', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fr', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fy', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ga', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gd', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gl', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gn', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gu', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-he', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hi', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hr', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hsb', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hu', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hy', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ia', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-id', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-is', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-it', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ja', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ka', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kab', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kk', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-km', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kn', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ko', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ku', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lg', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lt', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lv', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mai', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mk', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ml', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mn', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mr', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ms', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-my', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nb', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ne', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nl', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nn', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nso', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-oc', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-or', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pa', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pl', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pt', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ro', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ru', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-si', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sk', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sl', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sq', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sr', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sv', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sw', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-szl', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ta', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-te', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-th', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-tr', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-uk', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ur', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-uz', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-vi', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-xh', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zu', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-mozsymbols', 'pkgver': '99.0+build2-0ubuntu0.21.10.2'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-geckodriver / firefox-locale-af / etc');
}
