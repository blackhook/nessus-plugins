##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4686-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144787);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-5727",
    "CVE-2020-6851",
    "CVE-2020-8112",
    "CVE-2020-27814",
    "CVE-2020-27824",
    "CVE-2020-27841",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27845"
  );
  script_xref(name:"USN", value:"4686-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Ghostscript vulnerabilities (USN-4686-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4686-1 advisory.

  - In OpenJPEG 2.3.0, there is an integer overflow vulnerability in the opj_t1_encode_cblks function
    (openjp2/t1.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted bmp file. (CVE-2018-5727)

  - OpenJPEG through 2.3.1 has a heap-based buffer overflow in opj_t1_clbl_decode_processor in openjp2/t1.c
    because of lack of opj_j2k_update_image_dimensions validation. (CVE-2020-6851)

  - opj_t1_clbl_decode_processor in openjp2/t1.c in OpenJPEG 2.3.1 through 2020-01-28 has a heap-based buffer
    overflow in the qmfbid==1 case, a different issue than CVE-2020-6851. (CVE-2020-8112)

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4686-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8112");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs9-common");
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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'ghostscript', 'pkgver': '9.26~dfsg+0-0ubuntu0.16.04.14'},
    {'osver': '16.04', 'pkgname': 'ghostscript-x', 'pkgver': '9.26~dfsg+0-0ubuntu0.16.04.14'},
    {'osver': '16.04', 'pkgname': 'libgs-dev', 'pkgver': '9.26~dfsg+0-0ubuntu0.16.04.14'},
    {'osver': '16.04', 'pkgname': 'libgs9', 'pkgver': '9.26~dfsg+0-0ubuntu0.16.04.14'},
    {'osver': '16.04', 'pkgname': 'libgs9-common', 'pkgver': '9.26~dfsg+0-0ubuntu0.16.04.14'},
    {'osver': '18.04', 'pkgname': 'ghostscript', 'pkgver': '9.26~dfsg+0-0ubuntu0.18.04.14'},
    {'osver': '18.04', 'pkgname': 'ghostscript-x', 'pkgver': '9.26~dfsg+0-0ubuntu0.18.04.14'},
    {'osver': '18.04', 'pkgname': 'libgs-dev', 'pkgver': '9.26~dfsg+0-0ubuntu0.18.04.14'},
    {'osver': '18.04', 'pkgname': 'libgs9', 'pkgver': '9.26~dfsg+0-0ubuntu0.18.04.14'},
    {'osver': '18.04', 'pkgname': 'libgs9-common', 'pkgver': '9.26~dfsg+0-0ubuntu0.18.04.14'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ghostscript / ghostscript-x / libgs-dev / libgs9 / libgs9-common');
}