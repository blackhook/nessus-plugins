#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5321-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158817);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-0843",
    "CVE-2022-26381",
    "CVE-2022-26382",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26385",
    "CVE-2022-26387"
  );
  script_xref(name:"USN", value:"5321-1");
  script_xref(name:"IAVA", value:"2022-A-0103-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Firefox vulnerabilities (USN-5321-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5321-1 advisory.

  - If an attacker could control the contents of an iframe sandboxed with <code>allow-popups</code> but not
    <code>allow-scripts</code>, they were able to craft a link that, when clicked, would lead to JavaScript
    execution in violation of the sandbox. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and
    Thunderbird < 91.7. (CVE-2022-26384)

  - Mozilla developers Kershaw Chang, Ryan VanderMeulen, and Randell Jesup reported memory safety bugs present
    in Firefox 97. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    98. (CVE-2022-0843)

  - An attacker could have caused a use-after-free by forcing a text reflow in an SVG object leading to a
    potentially exploitable crash. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and
    Thunderbird < 91.7. (CVE-2022-26381)

  - While the text displayed in Autofill tooltips cannot be directly read by JavaScript, the text was rendered
    using page fonts. Side-channel attacks on the text by using specially crafted fonts could have lead to
    this text being inferred by the webpage. This vulnerability affects Firefox < 98. (CVE-2022-26382)

  - When resizing a popup after requesting fullscreen access, the popup would not display the fullscreen
    notification. This vulnerability affects Firefox < 98, Firefox ESR < 91.7, and Thunderbird < 91.7.
    (CVE-2022-26383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5321-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

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

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'firefox', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-dev', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-af', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-an', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-as', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-az', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-be', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-br', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-da', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-de', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-el', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-en', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-es', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-et', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-he', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-id', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-is', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-it', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-km', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-my', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-or', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-si', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-te', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-th', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '98.0+build3-0ubuntu0.18.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '98.0+build3-0ubuntu0.20.04.2'},
    {'osver': '21.10', 'pkgname': 'firefox', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-dev', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-geckodriver', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-af', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-an', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ar', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-as', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ast', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-az', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-be', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bg', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bn', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-br', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-bs', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ca', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cak', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cs', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-csb', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-cy', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-da', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-de', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-el', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-en', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-eo', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-es', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-et', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-eu', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fa', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fi', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fr', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-fy', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ga', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gd', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gl', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gn', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-gu', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-he', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hi', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hr', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hsb', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hu', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-hy', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ia', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-id', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-is', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-it', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ja', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ka', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kab', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kk', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-km', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-kn', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ko', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ku', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lg', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lt', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-lv', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mai', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mk', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ml', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mn', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-mr', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ms', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-my', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nb', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ne', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nl', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nn', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-nso', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-oc', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-or', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pa', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pl', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-pt', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ro', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ru', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-si', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sk', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sl', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sq', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sr', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sv', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-sw', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-szl', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ta', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-te', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-th', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-tr', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-uk', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-ur', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-uz', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-vi', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-xh', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-locale-zu', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'},
    {'osver': '21.10', 'pkgname': 'firefox-mozsymbols', 'pkgver': '98.0+build3-0ubuntu0.21.10.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-dev / firefox-geckodriver / firefox-locale-af / etc');
}
