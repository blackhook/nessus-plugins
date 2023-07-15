#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5954-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172575);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-25750",
    "CVE-2023-25751",
    "CVE-2023-25752",
    "CVE-2023-28160",
    "CVE-2023-28161",
    "CVE-2023-28162",
    "CVE-2023-28164",
    "CVE-2023-28176",
    "CVE-2023-28177"
  );
  script_xref(name:"USN", value:"5954-1");
  script_xref(name:"IAVA", value:"2023-A-0132-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Firefox vulnerabilities (USN-5954-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5954-1 advisory.

  - Under certain circumstances, a ServiceWorker's offline cache may have leaked to the file system when using
    private browsing mode.  (CVE-2023-25750)

  - Sometimes, when invalidating JIT code while following an iterator, the newly generated code could be
    overwritten incorrectly. This could lead to a potentially exploitable crash.  (CVE-2023-25751)

  - When accessing throttled streams, the count of available bytes needed to be checked in the calling
    function to be within bounds. This may have lead future code to be incorrect and vulnerable.
    (CVE-2023-25752)

  - When following a redirect to a publicly accessible web extension file, the URL may have been translated to
    the actual local path, leaking potentially sensitive information.  (CVE-2023-28160)

  - If temporary one-time permissions, such as the ability to use the Camera, were granted to a document
    loaded using a file: URL, that permission persisted in that tab for all other documents loaded from a
    file: URL. This is potentially dangerous if the local files came from different sources, such as in a
    download directory.  (CVE-2023-28161)

  - While implementing AudioWorklets, some code may have casted one type to another, invalid, dynamic type.
    This could have led to a potentially exploitable crash.  (CVE-2023-28162)

  - Dragging a URL from a cross-origin iframe that was removed during the drag could have led to user
    confusion and website spoofing attacks.  (CVE-2023-28164)

  - Mozilla developers Timothy Nikkel, Andrew McCreight, and the Mozilla Fuzzing Team reported memory safety
    bugs present in Thunderbird 102.8. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2023-28176)

  - Mozilla developers and community members Calixte Denizet, Gabriele Svelto, Andrew McCreight, and the
    Mozilla Fuzzing Team reported memory safety bugs present in Firefox 110. Some of these bugs showed
    evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2023-28177)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5954-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'firefox', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-dev', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-af', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-an', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-as', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-az', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-be', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-br', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-da', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-de', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-el', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-en', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-es', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-et', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-he', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-id', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-is', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-it', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-km', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-my', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-or', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-si', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-te', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-th', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '111.0+build2-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '111.0+build2-0ubuntu0.20.04.1'}
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
