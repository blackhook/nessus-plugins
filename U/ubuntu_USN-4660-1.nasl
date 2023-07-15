##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4660-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143445);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-4788",
    "CVE-2020-14351",
    "CVE-2020-14390",
    "CVE-2020-25211",
    "CVE-2020-25284",
    "CVE-2020-25285",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-28915"
  );
  script_xref(name:"USN", value:"4660-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4660-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4660-1 advisory.

  - IBM Power9 (AIX 7.1, 7.2, and VIOS 3.1) processors could allow a local user to obtain sensitive
    information from the data in the L1 cache under extenuating circumstances. IBM X-Force ID: 189296.
    (CVE-2020-4788)

  - A flaw was found in the Linux kernel in versions before 5.9-rc6. When changing screen size, an out-of-
    bounds memory write can occur leading to memory corruption or a denial of service. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled out. (CVE-2020-14390)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap
    rbd block devices, aka CID-f44d04e696fe. (CVE-2020-25284)

  - A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified
    other impact, aka CID-17743798d812. (CVE-2020-25285)

  - A flaw was found in the Linux kernel's implementation of biovecs in versions before 5.9-rc7. A zero-length
    biovec request issued by the block subsystem could cause the kernel to enter an infinite loop, causing a
    denial of service. This flaw allows a local attacker with basic privileges to issue requests to a block
    device, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2020-25641)

  - A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause
    the system to crash or cause a denial of service. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25643)

  - A flaw was found in the Linux kernel in versions before 5.9-rc7. Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read the traffic unencrypted. The main threat from
    this vulnerability is to data confidentiality. (CVE-2020-25645)

  - A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka CID-6735b4632def. (CVE-2020-28915)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4660-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1059-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1074-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1074-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1079-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1088-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1088-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1091-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1100-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1103-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-126-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-126-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-126-lowlatency");
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
  cve_list = make_list('CVE-2020-4788', 'CVE-2020-14351', 'CVE-2020-14390', 'CVE-2020-25211', 'CVE-2020-25284', 'CVE-2020-25285', 'CVE-2020-25641', 'CVE-2020-25643', 'CVE-2020-25645', 'CVE-2020-28915');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4660-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1059-oracle', 'pkgver': '4.15.0-1059.65~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1088-aws', 'pkgver': '4.15.0-1088.93~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1088-gcp', 'pkgver': '4.15.0-1088.101~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1100-azure', 'pkgver': '4.15.0-1100.111~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-126-generic', 'pkgver': '4.15.0-126.129~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-126-generic-lpae', 'pkgver': '4.15.0-126.129~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-126-lowlatency', 'pkgver': '4.15.0-126.129~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1088.82'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1100.93'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1100.93'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1088.89'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1088.89'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1059.48'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.126.125'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.126.125'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1059-oracle', 'pkgver': '4.15.0-1059.65'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1074-gke', 'pkgver': '4.15.0-1074.79'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1074-raspi2', 'pkgver': '4.15.0-1074.79'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1079-kvm', 'pkgver': '4.15.0-1079.81'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1088-aws', 'pkgver': '4.15.0-1088.93'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1088-gcp', 'pkgver': '4.15.0-1088.101'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1091-snapdragon', 'pkgver': '4.15.0-1091.100'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1100-azure', 'pkgver': '4.15.0-1100.111'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1103-oem', 'pkgver': '4.15.0-1103.114'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-126-generic', 'pkgver': '4.15.0-126.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-126-generic-lpae', 'pkgver': '4.15.0-126.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-126-lowlatency', 'pkgver': '4.15.0-126.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1088.90'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1100.73'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1088.106'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1074.78'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-4.15', 'pkgver': '4.15.0.1074.78'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1079.75'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.1103.107'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1059.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1074.71'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1091.94'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.126.113'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.126.113'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-4.15.0-1059-oracle / linux-image-4.15.0-1074-gke / etc');
}