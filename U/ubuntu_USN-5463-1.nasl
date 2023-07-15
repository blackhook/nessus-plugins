##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5463-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161922);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-46790",
    "CVE-2022-30783",
    "CVE-2022-30784",
    "CVE-2022-30785",
    "CVE-2022-30786",
    "CVE-2022-30787",
    "CVE-2022-30788",
    "CVE-2022-30789"
  );
  script_xref(name:"USN", value:"5463-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : NTFS-3G vulnerabilities (USN-5463-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5463-1 advisory.

  - ntfsck in NTFS-3G through 2021.8.22 has a heap-based buffer overflow involving buffer+512*3-2. NOTE: the
    upstream position is that ntfsck is deprecated; however, it is shipped by some Linux distributions.
    (CVE-2021-46790)

  - An invalid return code in fuse_kern_mount enables intercepting of libfuse-lite protocol traffic between
    NTFS-3G and the kernel in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30783)

  - A crafted NTFS image can cause heap exhaustion in ntfs_get_attribute_value in NTFS-3G through 2021.8.22.
    (CVE-2022-30784)

  - A file handle created in fuse_lib_opendir, and later used in fuse_lib_readdir, enables arbitrary memory
    read and write operations in NTFS-3G through 2021.8.22 when using libfuse-lite. (CVE-2022-30785)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_names_full_collate in NTFS-3G through
    2021.8.22. (CVE-2022-30786)

  - An integer underflow in fuse_lib_readdir enables arbitrary memory read operations in NTFS-3G through
    2021.8.22 when using libfuse-lite. (CVE-2022-30787)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_mft_rec_alloc in NTFS-3G through
    2021.8.22. (CVE-2022-30788)

  - A crafted NTFS image can cause a heap-based buffer overflow in ntfs_check_log_client_array in NTFS-3G
    through 2021.8.22. (CVE-2022-30789)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5463-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-30789");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libntfs-3g88");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libntfs-3g883");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libntfs-3g89");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ntfs-3g-dev");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libntfs-3g88', 'pkgver': '1:2017.3.23-2ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ntfs-3g', 'pkgver': '1:2017.3.23-2ubuntu0.18.04.4'},
    {'osver': '18.04', 'pkgname': 'ntfs-3g-dev', 'pkgver': '1:2017.3.23-2ubuntu0.18.04.4'},
    {'osver': '20.04', 'pkgname': 'libntfs-3g883', 'pkgver': '1:2017.3.23AR.3-3ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'ntfs-3g', 'pkgver': '1:2017.3.23AR.3-3ubuntu1.2'},
    {'osver': '20.04', 'pkgname': 'ntfs-3g-dev', 'pkgver': '1:2017.3.23AR.3-3ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'libntfs-3g883', 'pkgver': '1:2017.3.23AR.3-3ubuntu5.1'},
    {'osver': '21.10', 'pkgname': 'ntfs-3g', 'pkgver': '1:2017.3.23AR.3-3ubuntu5.1'},
    {'osver': '21.10', 'pkgname': 'ntfs-3g-dev', 'pkgver': '1:2017.3.23AR.3-3ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libntfs-3g89', 'pkgver': '1:2021.8.22-3ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'ntfs-3g', 'pkgver': '1:2021.8.22-3ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'ntfs-3g-dev', 'pkgver': '1:2021.8.22-3ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libntfs-3g88 / libntfs-3g883 / libntfs-3g89 / ntfs-3g / ntfs-3g-dev');
}
