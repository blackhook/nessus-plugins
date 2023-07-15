##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4578-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141448);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-10322",
    "CVE-2019-19448",
    "CVE-2020-14314",
    "CVE-2020-16119",
    "CVE-2020-16120",
    "CVE-2020-25212",
    "CVE-2020-26088"
  );
  script_bugtraq_id(103960);
  script_xref(name:"USN", value:"4578-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4578-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4578-1 advisory.

  - The xfs_dinode_verify function in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel through 4.16.3 allows
    local users to cause a denial of service (xfs_ilock_attr_map_shared invalid pointer dereference) via a
    crafted xfs image. (CVE-2018-10322)

  - In the Linux kernel 5.0.21 and 5.3.11, mounting a crafted btrfs filesystem image, performing some
    operations, and then making a syncfs system call can lead to a use-after-free in try_merge_free_space in
    fs/btrfs/free-space-cache.c because the pointer to a left data structure can be the same as the pointer to
    a right data structure. (CVE-2019-19448)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - A missing CAP_NET_RAW check in NFC socket creation in net/nfc/rawsock.c in the Linux kernel before 5.8.2
    could be used by local attackers to create raw sockets, bypassing security mechanisms, aka
    CID-26896f01467a. (CVE-2020-26088)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4578-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19448");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-16119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1056-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1057-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1072-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1073-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1077-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1085-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1086-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1086-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1089-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1098-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1099-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1099-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-120-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-120-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-120-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-121-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-121-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-121-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-4.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2018-10322', 'CVE-2019-19448', 'CVE-2020-14314', 'CVE-2020-16119', 'CVE-2020-16120', 'CVE-2020-25212', 'CVE-2020-26088');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4578-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1056-oracle', 'pkgver': '4.15.0-1056.61~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1085-aws', 'pkgver': '4.15.0-1085.90~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1086-gcp', 'pkgver': '4.15.0-1086.98~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1098-azure', 'pkgver': '4.15.0-1098.109~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-120-generic', 'pkgver': '4.15.0-120.122~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-120-generic-lpae', 'pkgver': '4.15.0-120.122~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-120-lowlatency', 'pkgver': '4.15.0-120.122~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1085.81'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1098.92'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1098.92'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1086.87'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1086.87'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1056.46'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.120.121'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.120.121'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1057-oracle', 'pkgver': '4.15.0-1057.62'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1072-gke', 'pkgver': '4.15.0-1072.76'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1073-raspi2', 'pkgver': '4.15.0-1073.78'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1077-kvm', 'pkgver': '4.15.0-1077.79'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1086-aws', 'pkgver': '4.15.0-1086.91'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1086-gcp', 'pkgver': '4.15.0-1086.98'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1089-snapdragon', 'pkgver': '4.15.0-1089.98'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1099-azure', 'pkgver': '4.15.0-1099.110'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1099-oem', 'pkgver': '4.15.0-1099.109'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-121-generic', 'pkgver': '4.15.0-121.123'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-121-generic-lpae', 'pkgver': '4.15.0-121.123'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-121-lowlatency', 'pkgver': '4.15.0-121.123'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1086.88'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1099.72'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1086.104'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1072.76'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-4.15', 'pkgver': '4.15.0.1072.76'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1077.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.1099.103'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1057.67'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1073.70'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1089.92'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.121.108'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.121.108'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-4.15.0-1056-oracle / linux-image-4.15.0-1057-oracle / etc');
}