##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4497-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(140592);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2016-9112",
    "CVE-2018-20847",
    "CVE-2018-21010",
    "CVE-2019-12973",
    "CVE-2020-6851",
    "CVE-2020-8112",
    "CVE-2020-15389"
  );
  script_xref(name:"USN", value:"4497-1");

  script_name(english:"Ubuntu 16.04 LTS : OpenJPEG vulnerabilities (USN-4497-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4497-1 advisory.

  - Floating Point Exception (aka FPE or divide by zero) in opj_pi_next_cprl function in openjp2/pi.c:523 in
    OpenJPEG 2.1.2. (CVE-2016-9112)

  - An improper computation of p_tx0, p_tx1, p_ty0 and p_ty1 in the function opj_get_encoding_parameters in
    openjp2/pi.c in OpenJPEG through 2.3.0 can lead to an integer overflow. (CVE-2018-20847)

  - OpenJPEG before 2.3.1 has a heap buffer overflow in color_apply_icc_profile in bin/common/color.c.
    (CVE-2018-21010)

  - In OpenJPEG 2.3.1, there is excessive iteration in the opj_t1_encode_cblks function of openjp2/t1.c.
    Remote attackers could leverage this vulnerability to cause a denial of service via a crafted bmp file.
    This issue is similar to CVE-2018-6616. (CVE-2019-12973)

  - OpenJPEG through 2.3.1 has a heap-based buffer overflow in opj_t1_clbl_decode_processor in openjp2/t1.c
    because of lack of opj_j2k_update_image_dimensions validation. (CVE-2020-6851)

  - opj_t1_clbl_decode_processor in openjp2/t1.c in OpenJPEG 2.3.1 through 2020-01-28 has a heap-based buffer
    overflow in the qmfbid==1 case, a different issue than CVE-2020-6851. (CVE-2020-8112)

  - jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a
    mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free
    may also be possible. This is related to calling opj_image_destroy twice. (CVE-2020-15389)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4497-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8112");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjp2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjp2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjp3d-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjp3d7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjpip-dec-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjpip-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjpip-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenjpip7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'libopenjp2-7', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjp2-7-dev', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjp2-tools', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjp3d-tools', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjp3d7', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjpip-dec-server', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjpip-server', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjpip-viewer', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'},
    {'osver': '16.04', 'pkgname': 'libopenjpip7', 'pkgver': '2.1.2-1.1+deb9u5build0.16.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenjp2-7 / libopenjp2-7-dev / libopenjp2-tools / libopenjp3d-tools / etc');
}
