##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4685-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144788);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-15389",
    "CVE-2020-27814",
    "CVE-2020-27823",
    "CVE-2020-27824",
    "CVE-2020-27841",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27845"
  );
  script_xref(name:"USN", value:"4685-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 20.04 LTS / 20.10 : OpenJPEG vulnerabilities (USN-4685-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 20.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4685-1 advisory.

  - jp2/opj_decompress.c in OpenJPEG through 2.3.1 has a use-after-free that can be triggered if there is a
    mix of valid and invalid files in a directory operated on by the decompressor. Triggering a double-free
    may also be possible. This is related to calling opj_image_destroy twice. (CVE-2020-15389)

  - There's a flaw in openjpeg in versions prior to 2.4.0 in src/lib/openjp2/pi.c. When an attacker is able to
    provide crafted input to be processed by the openjpeg encoder, this could cause an out-of-bounds read. The
    greatest impact from this flaw is to application availability. (CVE-2020-27841)

  - There's a flaw in openjpeg's t2 encoder in versions prior to 2.4.0. An attacker who is able to provide
    crafted input to be processed by openjpeg could cause a null pointer dereference. The highest impact of
    this flaw is to application availability. (CVE-2020-27842)

  - A flaw was found in OpenJPEG in versions prior to 2.4.0. This flaw allows an attacker to provide specially
    crafted input to the conversion or encoding functionality, causing an out-of-bounds read. The highest
    threat from this vulnerability is system availability. (CVE-2020-27843)

  - There's a flaw in src/lib/openjp2/pi.c of openjpeg in versions prior to 2.4.0. If an attacker is able to
    provide untrusted input to openjpeg's conversion/encoding functionality, they could cause an out-of-bounds
    read. The highest impact of this flaw is to application availability. (CVE-2020-27845)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4685-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
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
if (! preg(pattern:"^(20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '20.04', 'pkgname': 'libopenjp2-7', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjp2-7-dev', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjp2-tools', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjp3d-tools', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjp3d7', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjpip-dec-server', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjpip-server', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjpip-viewer', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libopenjpip7', 'pkgver': '2.3.1-1ubuntu4.20.04.1'},
    {'osver': '20.10', 'pkgname': 'libopenjp2-7', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjp2-7-dev', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjp2-tools', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjp3d-tools', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjp3d7', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjpip-dec-server', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjpip-server', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjpip-viewer', 'pkgver': '2.3.1-1ubuntu4.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libopenjpip7', 'pkgver': '2.3.1-1ubuntu4.20.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenjp2-7 / libopenjp2-7-dev / libopenjp2-tools / libopenjp3d-tools / etc');
}