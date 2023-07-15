#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6143-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176886);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-34414",
    "CVE-2023-34415",
    "CVE-2023-34416",
    "CVE-2023-34417"
  );
  script_xref(name:"USN", value:"6143-1");
  script_xref(name:"IAVA", value:"2023-A-0277-S");

  script_name(english:"Ubuntu 20.04 LTS : Firefox vulnerabilities (USN-6143-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6143-1 advisory.

  - The error page for sites with invalid TLS certificates was missing the activation-delay Firefox uses to
    protect prompts and permission dialogs from attacks that exploit human response time delays. If a
    malicious page elicited user clicks in precise locations immediately before navigating to a site with a
    certificate error and made the renderer extremely busy at the same time, it could create a gap between
    when the error page was loaded and when the display actually refreshed. With the right timing the elicited
    clicks could land in that gap and  activate the button that overrides the certificate error for that site.
    (CVE-2023-34414)

  - When choosing a site-isolated process for a document loaded from a data: URL that was the result of a
    redirect, Firefox would load that document in the same process as the site that issued the redirect. This
    bypassed the site-isolation protections against Spectre-like attacks on sites that host an open
    redirect. Firefox no longer follows HTTP redirects to data: URLs.  (CVE-2023-34415)

  - Mozilla developers and community members Gabriele Svelto, Andrew McCreight, the Mozilla Fuzzing Team, Sean
    Feng, and Sebastian Hengst reported memory safety bugs present in Firefox 113 and Firefox ESR 102.11. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code.  (CVE-2023-34416)

  - Mozilla developers and community members Andrew McCreight, Randell Jesup, and the Mozilla Fuzzing Team
    reported memory safety bugs present in Firefox 113. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2023-34417)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6143-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox-locale-tg");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tg', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '114.0+build3-0ubuntu0.20.04.1'}
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
