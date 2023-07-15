#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5733-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168010);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2017-6888", "CVE-2020-0499", "CVE-2021-0561");
  script_xref(name:"USN", value:"5733-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : FLAC vulnerabilities (USN-5733-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5733-1 advisory.

  - An error in the read_metadata_vorbiscomment_() function (src/libFLAC/stream_decoder.c) in FLAC version
    1.3.2 can be exploited to cause a memory leak via a specially crafted FLAC file. (CVE-2017-6888)

  - In FLAC__bitreader_read_rice_signed_block of bitreader.c, there is a possible out of bounds read due to a
    heap buffer overflow. This could lead to remote information disclosure with no additional execution
    privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-11Android
    ID: A-156076070 (CVE-2020-0499)

  - In append_to_verify_fifo_interleaved_ of stream_encoder.c, there is a possible out of bounds write due to
    a missing bounds check. This could lead to local information disclosure with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions:
    Android-11Android ID: A-174302683 (CVE-2021-0561)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5733-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac++6v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflac8");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'flac', 'pkgver': '1.3.1-4ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libflac++-dev', 'pkgver': '1.3.1-4ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libflac++6v5', 'pkgver': '1.3.1-4ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libflac-dev', 'pkgver': '1.3.1-4ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'libflac8', 'pkgver': '1.3.1-4ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'flac', 'pkgver': '1.3.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libflac++-dev', 'pkgver': '1.3.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libflac++6v5', 'pkgver': '1.3.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libflac-dev', 'pkgver': '1.3.2-1ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libflac8', 'pkgver': '1.3.2-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'flac', 'pkgver': '1.3.3-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libflac++-dev', 'pkgver': '1.3.3-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libflac++6v5', 'pkgver': '1.3.3-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libflac-dev', 'pkgver': '1.3.3-1ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libflac8', 'pkgver': '1.3.3-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'flac', 'pkgver': '1.3.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libflac++-dev', 'pkgver': '1.3.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libflac++6v5', 'pkgver': '1.3.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libflac-dev', 'pkgver': '1.3.3-2ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libflac8', 'pkgver': '1.3.3-2ubuntu0.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flac / libflac++-dev / libflac++6v5 / libflac-dev / libflac8');
}
