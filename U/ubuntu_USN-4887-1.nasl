##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4887-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148034);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2021-3444",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );
  script_xref(name:"USN", value:"4887-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : Linux kernel vulnerabilities (USN-4887-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4887-1 advisory.

  - An issue was discovered in the Linux kernel before 5.11.8. kernel/bpf/verifier.c performs undesirable out-
    of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory, aka CID-f232326f6966. This affects
    pointer types that do not define a ptr_limit. (CVE-2020-27170)

  - An issue was discovered in the Linux kernel before 5.11.8. kernel/bpf/verifier.c has an off-by-one error
    (with a resultant integer underflow) affecting out-of-bounds speculation on pointer arithmetic, leading to
    side-channel attacks that defeat Spectre mitigations and obtain sensitive information from kernel memory,
    aka CID-10d2bb2e6b1d. (CVE-2020-27171)

  - The bpf verifier in the Linux kernel did not properly handle mod32 destination register truncation when
    the source register was known to be 0. A local attacker with the ability to load bpf programs could use
    this gain out-of-bounds reads in kernel memory leading to information disclosure (kernel memory), and
    possibly out-of-bounds writes that could potentially lead to code execution. This issue was addressed in
    the upstream kernel in commit 9b00f1b78809 (bpf: Fix truncation handling for mod32 dst reg wrt zero) and
    in Linux stable kernels 5.11.2, 5.10.19, and 5.4.101. (CVE-2021-3444)

  - An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI
    subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the
    pointer to an iscsi_transport struct in the kernel module's global variables. (CVE-2021-27363)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4887-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.10.0-1019-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1038-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1041-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-72-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-72-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1012-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1032-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1036-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1039-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1040-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1041-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1041-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1043-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-70-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-70-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-70-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.6.0-1052-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1019-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1019-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1022-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1024-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1026-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1026-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-1027-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-48-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-48-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-48-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.8.0-48-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-20.04b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-20.04-edge");
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
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-27170', 'CVE-2020-27171', 'CVE-2021-3444', 'CVE-2021-27363', 'CVE-2021-27364', 'CVE-2021-27365');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4887-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-1038-raspi2', 'pkgver': '5.3.0-1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-1041-gke', 'pkgver': '5.3.0-1041.44'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-72-generic', 'pkgver': '5.3.0-72.68'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.3.0-72-lowlatency', 'pkgver': '5.3.0-72.68'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1012-gkeop', 'pkgver': '5.4.0-1012.13~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1032-raspi', 'pkgver': '5.4.0-1032.35~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1039-gke', 'pkgver': '5.4.0-1039.41~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1040-gcp', 'pkgver': '5.4.0-1040.43~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1041-aws', 'pkgver': '5.4.0-1041.43~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1041-oracle', 'pkgver': '5.4.0-1041.44~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1043-azure', 'pkgver': '5.4.0-1043.45~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-70-generic', 'pkgver': '5.4.0-70.78~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-70-generic-lpae', 'pkgver': '5.4.0-70.78~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-70-lowlatency', 'pkgver': '5.4.0-70.78~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1041.24'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1041.24'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1043.23'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1043.23'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1040.27'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1040.27'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.3', 'pkgver': '5.3.0.1041.24'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1039.41~18.04.6'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.3', 'pkgver': '5.3.0.72.129'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1012.13~18.04.13'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1041.44~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1041.44~18.04.23'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1032.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1032.34'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.3.0.1038.27'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.70.78~18.04.63'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.10.0-1019-oem', 'pkgver': '5.10.0-1019.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1012-gkeop', 'pkgver': '5.4.0-1012.13'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1032-raspi', 'pkgver': '5.4.0-1032.35'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1036-kvm', 'pkgver': '5.4.0-1036.37'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1040-gcp', 'pkgver': '5.4.0-1040.43'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1041-aws', 'pkgver': '5.4.0-1041.43'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1041-oracle', 'pkgver': '5.4.0-1041.44'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1043-azure', 'pkgver': '5.4.0-1043.45'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-70-generic', 'pkgver': '5.4.0-70.78'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-70-generic-lpae', 'pkgver': '5.4.0-70.78'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-70-lowlatency', 'pkgver': '5.4.0-70.78'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.6.0-1052-oem', 'pkgver': '5.6.0-1052.56'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-48-generic', 'pkgver': '5.8.0-48.54~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-48-generic-64k', 'pkgver': '5.8.0-48.54~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-48-generic-lpae', 'pkgver': '5.8.0-48.54~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.8.0-48-lowlatency', 'pkgver': '5.8.0-48.54~20.04.1'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1041.42'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1043.41'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1040.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1012.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1012.15'},
    {'osver': '20.04', 'pkgname': 'linux-image-kvm', 'pkgver': '5.4.0.1036.34'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.6.0.1052.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04-edge', 'pkgver': '5.10.0.1019.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-20.04b', 'pkgver': '5.10.0.1019.20'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1041.38'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1032.67'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.70.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.48.54~20.04.32'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1019-raspi', 'pkgver': '5.8.0-1019.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1019-raspi-nolpae', 'pkgver': '5.8.0-1019.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1022-kvm', 'pkgver': '5.8.0-1022.24'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1024-oracle', 'pkgver': '5.8.0-1024.25'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1026-azure', 'pkgver': '5.8.0-1026.28'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1026-gcp', 'pkgver': '5.8.0-1026.27'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-1027-aws', 'pkgver': '5.8.0-1027.29'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-48-generic', 'pkgver': '5.8.0-48.54'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-48-generic-64k', 'pkgver': '5.8.0-48.54'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-48-generic-lpae', 'pkgver': '5.8.0-48.54'},
    {'osver': '20.10', 'pkgname': 'linux-image-5.8.0-48-lowlatency', 'pkgver': '5.8.0-48.54'},
    {'osver': '20.10', 'pkgname': 'linux-image-aws', 'pkgver': '5.8.0.1027.29'},
    {'osver': '20.10', 'pkgname': 'linux-image-azure', 'pkgver': '5.8.0.1026.26'},
    {'osver': '20.10', 'pkgname': 'linux-image-gcp', 'pkgver': '5.8.0.1026.26'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-64k-hwe-20.04-edge', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-hwe-20.04-edge', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-generic-lpae-hwe-20.04-edge', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-gke', 'pkgver': '5.8.0.1026.26'},
    {'osver': '20.10', 'pkgname': 'linux-image-kvm', 'pkgver': '5.8.0.1022.24'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-lowlatency-hwe-20.04-edge', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-oem-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-oracle', 'pkgver': '5.8.0.1024.23'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi', 'pkgver': '5.8.0.1019.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-raspi-nolpae', 'pkgver': '5.8.0.1019.22'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04', 'pkgver': '5.8.0.48.53'},
    {'osver': '20.10', 'pkgname': 'linux-image-virtual-hwe-20.04-edge', 'pkgver': '5.8.0.48.53'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.10.0-1019-oem / linux-image-5.3.0-1038-raspi2 / etc');
}