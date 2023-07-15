##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5405-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160724);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2017-9216", "CVE-2020-12268");
  script_xref(name:"USN", value:"5405-1");

  script_name(english:"Ubuntu 16.04 LTS : jbig2dec vulnerabilities (USN-5405-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5405-1 advisory.

  - libjbig2dec.a in Artifex jbig2dec 0.13, as used in MuPDF and Ghostscript, has a NULL pointer dereference
    in the jbig2_huffman_get function in jbig2_huffman.c. For example, the jbig2dec utility will crash
    (segmentation fault) when parsing an invalid file. (CVE-2017-9216)

  - jbig2_image_compose in jbig2_image.c in Artifex jbig2dec before 0.18 has a heap-based buffer overflow.
    (CVE-2020-12268)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5405-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected jbig2dec, libjbig2dec0 and / or libjbig2dec0-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12268");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jbig2dec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjbig2dec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjbig2dec0-dev");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'jbig2dec', 'pkgver': '0.12+20150918-1ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libjbig2dec0', 'pkgver': '0.12+20150918-1ubuntu0.1+esm2'},
    {'osver': '16.04', 'pkgname': 'libjbig2dec0-dev', 'pkgver': '0.12+20150918-1ubuntu0.1+esm2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbig2dec / libjbig2dec0 / libjbig2dec0-dev');
}
