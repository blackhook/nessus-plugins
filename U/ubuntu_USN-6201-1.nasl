#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6201-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177998);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2023-3482",
    "CVE-2023-37201",
    "CVE-2023-37202",
    "CVE-2023-37203",
    "CVE-2023-37204",
    "CVE-2023-37205",
    "CVE-2023-37206",
    "CVE-2023-37207",
    "CVE-2023-37208",
    "CVE-2023-37209",
    "CVE-2023-37210",
    "CVE-2023-37211",
    "CVE-2023-37212"
  );
  script_xref(name:"USN", value:"6201-1");
  script_xref(name:"IAVA", value:"2023-A-0328");

  script_name(english:"Ubuntu 20.04 LTS : Firefox vulnerabilities (USN-6201-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-6201-1 advisory.

  - When Firefox is configured to block storage of all cookies, it was still possible to store data in
    localstorage by using an iframe with a source of 'about:blank'. This could have led to malicious websites
    storing tracking data without permission. This vulnerability affects Firefox < 115. (CVE-2023-3482)

  - An attacker could have triggered a use-after-free condition when creating a WebRTC connection over HTTPS.
    This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37201)

  - Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to
    be stored in the main compartment resulting in a use-after-free. This vulnerability affects Firefox < 115,
    Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37202)

  - Insufficient validation in the Drag and Drop API in conjunction with social engineering, may have allowed
    an attacker to trick end-users into creating a shortcut to local system files. This could have been
    leveraged to execute arbitrary code. This vulnerability affects Firefox < 115. (CVE-2023-37203)

  - A website could have obscured the fullscreen notification by using an option element by introducing lag
    via an expensive computational function. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 115. (CVE-2023-37204)

  - The use of RTL Arabic characters in the address bar may have allowed for URL spoofing. This vulnerability
    affects Firefox < 115. (CVE-2023-37205)

  - Uploading files which contain symlinks may have allowed an attacker to trick a user into submitting
    sensitive data to a malicious website. This vulnerability affects Firefox < 115. (CVE-2023-37206)

  - A website could have obscured the fullscreen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13.
    (CVE-2023-37207)

  - When opening Diagcab files, Firefox did not warn the user that these files may contain malicious code.
    This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and Thunderbird < 102.13. (CVE-2023-37208)

  - A use-after-free condition existed in `NotifyOnHistoryReload` where a `LoadingSessionHistoryEntry` object
    was freed and a reference to that object remained. This resulted in a potentially exploitable condition
    when the reference to that object was later reused. This vulnerability affects Firefox < 115.
    (CVE-2023-37209)

  - A website could prevent a user from exiting full-screen mode via alert and prompt calls. This could lead
    to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 115.
    (CVE-2023-37210)

  - Memory safety bugs present in Firefox 114, Firefox ESR 102.12, and Thunderbird 102.12. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 115, Firefox ESR < 102.13, and
    Thunderbird < 102.13. (CVE-2023-37211)

  - Memory safety bugs present in Firefox 114. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 115. (CVE-2023-37212)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6201-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-37211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/05");

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
    {'osver': '20.04', 'pkgname': 'firefox', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-dev', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-geckodriver', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-af', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-an', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ar', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-as', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ast', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-az', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-be', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bg', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bn', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-br', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-bs', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ca', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cak', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cs', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-csb', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-cy', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-da', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-de', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-el', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-en', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eo', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-es', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-et', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-eu', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fa', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fi', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fr', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-fy', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ga', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gd', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gl', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gn', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-gu', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-he', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hi', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hr', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hsb', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hu', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-hy', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ia', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-id', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-is', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-it', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ja', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ka', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kab', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kk', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-km', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-kn', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ko', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ku', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lg', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lt', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-lv', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mai', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mk', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ml', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mn', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-mr', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ms', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-my', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nb', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ne', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nl', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nn', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-nso', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-oc', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-or', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pa', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pl', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-pt', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ro', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ru', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-si', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sk', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sl', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sq', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sr', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sv', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-sw', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-szl', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ta', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-te', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tg', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-th', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-tr', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uk', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-ur', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-uz', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-vi', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-xh', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hans', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zh-hant', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-locale-zu', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'firefox-mozsymbols', 'pkgver': '115.0+build2-0ubuntu0.20.04.3'}
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
