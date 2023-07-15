#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5631-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165321);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2018-11813",
    "CVE-2020-17541",
    "CVE-2020-35538",
    "CVE-2021-46822"
  );
  script_xref(name:"USN", value:"5631-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : libjpeg-turbo vulnerabilities (USN-5631-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5631-1 advisory.

  - libjpeg 9c has a large loop because read_pixel in rdtarga.c mishandles EOF. (CVE-2018-11813)

  - Libjpeg-turbo all version have a stack-based buffer overflow in the transform component. A remote
    attacker can send a malformed jpeg file to the service and cause arbitrary code execution or denial of
    service of the target service. (CVE-2020-17541)

  - A crafted input file could cause a null pointer dereference in jcopy_sample_rows() when processed by
    libjpeg-turbo. (CVE-2020-35538)

  - The PPM reader in libjpeg-turbo through 2.0.90 mishandles use of tjLoadImage for loading a 16-bit binary
    PPM file into a grayscale buffer and loading a 16-bit binary PGM file into an RGB buffer. This is related
    to a heap-based buffer overflow in the get_word_rgb_row function in rdppm.c. (CVE-2021-46822)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5631-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjpeg-turbo-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjpeg-turbo-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjpeg-turbo8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjpeg-turbo8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libturbojpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libturbojpeg0-dev");
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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libjpeg-turbo-progs', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libjpeg-turbo-test', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libjpeg-turbo8', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libjpeg-turbo8-dev', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libturbojpeg', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '18.04', 'pkgname': 'libturbojpeg0-dev', 'pkgver': '1.5.2-0ubuntu5.18.04.6'},
    {'osver': '20.04', 'pkgname': 'libjpeg-turbo-progs', 'pkgver': '2.0.3-0ubuntu1.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libjpeg-turbo-test', 'pkgver': '2.0.3-0ubuntu1.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libjpeg-turbo8', 'pkgver': '2.0.3-0ubuntu1.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libjpeg-turbo8-dev', 'pkgver': '2.0.3-0ubuntu1.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libturbojpeg', 'pkgver': '2.0.3-0ubuntu1.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libturbojpeg0-dev', 'pkgver': '2.0.3-0ubuntu1.20.04.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjpeg-turbo-progs / libjpeg-turbo-test / libjpeg-turbo8 / etc');
}
