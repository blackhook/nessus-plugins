##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4752-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147982);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-10135",
    "CVE-2020-14314",
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-24490",
    "CVE-2020-25212",
    "CVE-2020-25284",
    "CVE-2020-25641",
    "CVE-2020-25643",
    "CVE-2020-25704",
    "CVE-2020-27152",
    "CVE-2020-27815",
    "CVE-2020-28588",
    "CVE-2020-28915",
    "CVE-2020-29368",
    "CVE-2020-29369",
    "CVE-2020-29371",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-35508"
  );
  script_xref(name:"USN", value:"4752-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-4752-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4752-1 advisory.

  - Legacy pairing and secure-connections pairing authentication in Bluetooth BR/EDR Core Specification v5.2
    and earlier may allow an unauthenticated user to complete authentication without pairing credentials via
    adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or
    slave to pair with a previously paired remote device to successfully complete the authentication procedure
    without knowing the link key. (CVE-2020-10135)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

  - Use-after-free vulnerability in fs/block_dev.c in the Linux kernel before 5.8 allows local users to gain
    privileges or cause a denial of service by leveraging improper access to a certain error field.
    (CVE-2020-15436)

  - The Linux kernel before version 5.8 is vulnerable to a NULL pointer dereference in
    drivers/tty/serial/8250/8250_core.c:serial8250_isa_init_ports() that allows local users to cause a denial
    of service by using the p->serial_in pointer which uninitialized. (CVE-2020-15437)

  - Improper buffer restrictions in BlueZ may allow an unauthenticated user to potentially enable denial of
    service via adjacent access. This affects all Linux kernel versions that support BlueZ. (CVE-2020-24490)

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - The rbd block device driver in drivers/block/rbd.c in the Linux kernel through 5.8.9 used incomplete
    permission checking for access to rbd devices, which could be leveraged by local attackers to map or unmap
    rbd block devices, aka CID-f44d04e696fe. (CVE-2020-25284)

  - A flaw was found in the Linux kernel's implementation of biovecs in versions before 5.9-rc7. A zero-length
    biovec request issued by the block subsystem could cause the kernel to enter an infinite loop, causing a
    denial of service. This flaw allows a local attacker with basic privileges to issue requests to a block
    device, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2020-25641)

  - A flaw was found in the HDLC_PPP module of the Linux kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input validation in the ppp_cp_parse_cr function which can cause
    the system to crash or cause a denial of service. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25643)

  - A flaw memory leak in the Linux kernel performance monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this flaw to starve the resources causing denial of
    service. (CVE-2020-25704)

  - An issue was discovered in ioapic_lazy_update_eoi in arch/x86/kvm/ioapic.c in the Linux kernel before
    5.9.2. It has an infinite loop related to improper interaction between a resampler and edge triggering,
    aka CID-77377064c3a9. (CVE-2020-27152)

  - A buffer over-read (at the framebuffer layer) in the fbcon code in the Linux kernel before 5.8.15 could be
    used by local attackers to read kernel memory, aka CID-6735b4632def. (CVE-2020-28915)

  - An issue was discovered in __split_huge_pmd in mm/huge_memory.c in the Linux kernel before 5.7.5. The
    copy-on-write implementation can grant unintended write access because of a race condition in a THP
    mapcount check, aka CID-c444eb564fb1. (CVE-2020-29368)

  - An issue was discovered in mm/mmap.c in the Linux kernel before 5.7.11. There is a race condition between
    certain expand functions (expand_downwards and expand_upwards) and page-table free operations from an
    munmap call, aka CID-246c320a8cfe. (CVE-2020-29369)

  - An issue was discovered in romfs_dev_read in fs/romfs/storage.c in the Linux kernel before 5.8.4.
    Uninitialized memory leaks to userspace, aka CID-bcf85fcedfdd. (CVE-2020-29371)

  - A locking inconsistency issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may allow a read-after-free attack against TIOCGSID,
    aka CID-c8bcd9c5be24. (CVE-2020-29660)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4752-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-image-5.6.0-1048-oem and / or linux-image-oem-20.04 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.6.0-1048-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-10135', 'CVE-2020-14314', 'CVE-2020-15436', 'CVE-2020-15437', 'CVE-2020-24490', 'CVE-2020-25212', 'CVE-2020-25284', 'CVE-2020-25641', 'CVE-2020-25643', 'CVE-2020-25704', 'CVE-2020-27152', 'CVE-2020-27815', 'CVE-2020-28588', 'CVE-2020-28915', 'CVE-2020-29368', 'CVE-2020-29369', 'CVE-2020-29371', 'CVE-2020-29660', 'CVE-2020-29661', 'CVE-2020-35508');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4752-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-image-5.6.0-1048-oem', 'pkgver': '5.6.0-1048.52'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.6.0.1048.44'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.6.0-1048-oem / linux-image-oem-20.04');
}