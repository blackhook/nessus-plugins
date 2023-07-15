#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5840-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170961);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id(
    "CVE-2018-5786",
    "CVE-2020-25467",
    "CVE-2021-27345",
    "CVE-2021-27347",
    "CVE-2022-26291",
    "CVE-2022-28044"
  );
  script_xref(name:"USN", value:"5840-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : Long Range ZIP vulnerabilities (USN-5840-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-5840-1 advisory.

  - In Long Range Zip (aka lrzip) 0.631, there is an infinite loop and application hang in the get_fileinfo
    function (lrzip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted lrz file. (CVE-2018-5786)

  - A null pointer dereference was discovered lzo_decompress_buf in stream.c in Irzip 0.621 which allows an
    attacker to cause a denial of service (DOS) via a crafted compressed file. (CVE-2020-25467)

  - A null pointer dereference was discovered in ucompthread in stream.c in Irzip 0.631 which allows attackers
    to cause a denial of service (DOS) via a crafted compressed file. (CVE-2021-27345)

  - Use after free in lzma_decompress_buf function in stream.c in Irzip 0.631 allows attackers to cause Denial
    of Service (DoS) via a crafted compressed file. (CVE-2021-27347)

  - lrzip v0.641 was discovered to contain a multiple concurrency use-after-free between the functions
    zpaq_decompress_buf() and clear_rulist(). This vulnerability allows attackers to cause a Denial of Service
    (DoS) via a crafted Irz file. (CVE-2022-26291)

  - Irzip v0.640 was discovered to contain a heap memory corruption via the component
    lrzip.c:initialise_control. (CVE-2022-28044)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5840-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected lrzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28044");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lrzip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'lrzip', 'pkgver': '0.621-1ubuntu0.1~esm2'},
    {'osver': '18.04', 'pkgname': 'lrzip', 'pkgver': '0.631-1+deb9u3build0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'lrzip', 'pkgver': '0.631+git180528-1+deb10u1build0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'lrzip', 'pkgver': '0.651-2ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'lrzip', 'pkgver': '0.651-2ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lrzip');
}
