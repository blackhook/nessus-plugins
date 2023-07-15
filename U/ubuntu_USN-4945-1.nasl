#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4945-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149416);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2020-25639",
    "CVE-2021-28038",
    "CVE-2021-28375",
    "CVE-2021-28660",
    "CVE-2021-29265",
    "CVE-2021-29650",
    "CVE-2021-30002"
  );
  script_xref(name:"USN", value:"4945-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-4945-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4945-1 advisory.

  - A NULL pointer dereference flaw was found in the Linux kernel's GPU Nouveau driver functionality in
    versions prior to 5.12-rc1 in the way the user calls ioctl DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC. This flaw
    allows a local user to crash the system. (CVE-2020-25639)

  - An issue was discovered in the Linux kernel through 5.11.3, as used with Xen PV. A certain part of the
    netback driver lacks necessary treatment of errors such as failed memory allocations (as a result of
    changes to the handling of grant mapping errors). A host OS denial of service may occur during misbehavior
    of a networking frontend driver. NOTE: this issue exists because of an incomplete fix for CVE-2021-26931.
    (CVE-2021-28038)

  - An issue was discovered in the Linux kernel through 5.11.6. fastrpc_internal_invoke in
    drivers/misc/fastrpc.c does not prevent user applications from sending kernel RPC messages, aka
    CID-20c40794eb85. This is a related issue to CVE-2019-2308. (CVE-2021-28375)

  - rtw_wx_set_scan in drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the Linux kernel through 5.11.6
    allows writing beyond the end of the ->ssid[] array. NOTE: from the perspective of kernel.org releases,
    CVE IDs are not normally used for drivers/staging/* (unfinished work); however, system integrators may
    have situations in which a drivers/staging issue is relevant to their own customer base. (CVE-2021-28660)

  - An issue was discovered in the Linux kernel before 5.11.7. usbip_sockfd_store in
    drivers/usb/usbip/stub_dev.c allows attackers to cause a denial of service (GPF) because the stub-up
    sequence has race conditions during an update of the local and shared status, aka CID-9380afd6df70.
    (CVE-2021-29265)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

  - An issue was discovered in the Linux kernel before 5.11.3 when a webcam device exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak for large arguments, aka CID-fb18802a338b.
    (CVE-2021-30002)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4945-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1015-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1039-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1043-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1043-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1044-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1045-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1047-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1048-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-73-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-73-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-73-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-25639', 'CVE-2021-28038', 'CVE-2021-28375', 'CVE-2021-28660', 'CVE-2021-29265', 'CVE-2021-29650', 'CVE-2021-30002');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4945-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1015-gkeop', 'pkgver': '5.4.0-1015.16~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1043-gcp', 'pkgver': '5.4.0-1043.46~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1043-gke', 'pkgver': '5.4.0-1043.45~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1044-oracle', 'pkgver': '5.4.0-1044.47~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1047-azure', 'pkgver': '5.4.0-1047.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1048-aws', 'pkgver': '5.4.0-1048.50~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-73-generic', 'pkgver': '5.4.0-73.82~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-73-generic-lpae', 'pkgver': '5.4.0-73.82~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-73-lowlatency', 'pkgver': '5.4.0-73.82~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1048.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1048.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1047.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1047.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1043.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1043.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1043.45~18.04.9'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1015.16~18.04.16'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1044.47~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1044.47~18.04.26'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.73.82~18.04.66'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1015-gkeop', 'pkgver': '5.4.0-1015.16'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1039-kvm', 'pkgver': '5.4.0-1039.40'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1043-gcp', 'pkgver': '5.4.0-1043.46'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1043-gke', 'pkgver': '5.4.0-1043.45'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1045-oracle', 'pkgver': '5.4.0-1045.49+1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1047-azure', 'pkgver': '5.4.0-1047.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1048-aws', 'pkgver': '5.4.0-1048.50'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-73-generic', 'pkgver': '5.4.0-73.82'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-73-generic-lpae', 'pkgver': '5.4.0-73.82'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-73-lowlatency', 'pkgver': '5.4.0-73.82'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1048.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1047.45'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1043.52'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.4.0.1043.52'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1043.52'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1015.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1015.18'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1039.37'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1045.44'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.73.76'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.73.76'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.4.0-1015-gkeop / linux-image-5.4.0-1039-kvm / etc');
}