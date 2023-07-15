##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4763-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147998);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-25289",
    "CVE-2021-25290",
    "CVE-2021-25291",
    "CVE-2021-25292",
    "CVE-2021-25293",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923"
  );
  script_xref(name:"USN", value:"4763-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Pillow vulnerabilities (USN-4763-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4763-1 advisory.

  - An issue was discovered in Pillow before 8.1.1. TiffDecode has a heap-based buffer overflow when decoding
    crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode. NOTE: this
    issue exists because of an incomplete fix for CVE-2020-35654. (CVE-2021-25289)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is an out-of-bounds read in
    TiffreadRGBATile via invalid tile boundaries. (CVE-2021-25291)

  - An issue was discovered in Pillow before 8.1.1. The PDF parser allows a regular expression DoS (ReDoS)
    attack via a crafted PDF file because of a catastrophic backtracking regex. (CVE-2021-25292)

  - An issue was discovered in Pillow before 8.1.1. There is an out-of-bounds read in SGIRleDecode.c.
    (CVE-2021-25293)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for a BLP container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27921)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICNS container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27922)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICO container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27923)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4763-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25289");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pil.imagetk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pil.imagetk");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'python-imaging', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python-pil', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python-pil.imagetk', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python3-pil', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '16.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '3.1.2-0ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'python-pil', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python3-pil', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '18.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '5.1.0-1ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'python3-pil', 'pkgver': '7.0.0-4ubuntu0.3'},
    {'osver': '20.04', 'pkgname': 'python3-pil.imagetk', 'pkgver': '7.0.0-4ubuntu0.3'},
    {'osver': '20.10', 'pkgname': 'python3-pil', 'pkgver': '7.2.0-1ubuntu0.2'},
    {'osver': '20.10', 'pkgname': 'python3-pil.imagetk', 'pkgver': '7.2.0-1ubuntu0.2'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-imaging / python-pil / python-pil.imagetk / python3-pil / etc');
}