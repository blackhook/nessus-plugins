#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154404);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2015-4001",
    "CVE-2015-4002",
    "CVE-2015-4003",
    "CVE-2015-4004",
    "CVE-2015-8967",
    "CVE-2016-1583",
    "CVE-2017-9725",
    "CVE-2017-11089",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25673",
    "CVE-2020-36385",
    "CVE-2021-0129",
    "CVE-2021-3347",
    "CVE-2021-3428",
    "CVE-2021-3483",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3609",
    "CVE-2021-20292",
    "CVE-2021-22555",
    "CVE-2021-28964",
    "CVE-2021-29154",
    "CVE-2021-29265",
    "CVE-2021-31916",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33909",
    "CVE-2021-34693"
  );
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2021-2588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Integer signedness error in the oz_hcd_get_desc_cnf function in drivers/staging/ozwpan/ozhcd.c in the
    OZWPAN driver in the Linux kernel through 4.0.5 allows remote attackers to cause a denial of service
    (system crash) or possibly execute arbitrary code via a crafted packet. (CVE-2015-4001)

  - drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver in the Linux kernel through 4.0.5 does not ensure
    that certain length values are sufficiently large, which allows remote attackers to cause a denial of
    service (system crash or large loop) or possibly execute arbitrary code via a crafted packet, related to
    the (1) oz_usb_rx and (2) oz_usb_handle_ep_data functions. (CVE-2015-4002)

  - The oz_usb_handle_ep_data function in drivers/staging/ozwpan/ozusbsvc1.c in the OZWPAN driver in the Linux
    kernel through 4.0.5 allows remote attackers to cause a denial of service (divide-by-zero error and system
    crash) via a crafted packet. (CVE-2015-4003)

  - The OZWPAN driver in the Linux kernel through 4.0.5 relies on an untrusted length field during packet
    parsing, which allows remote attackers to obtain sensitive information from kernel memory or cause a
    denial of service (out-of-bounds read and system crash) via a crafted packet. (CVE-2015-4004)

  - arch/arm64/kernel/sys.c in the Linux kernel before 4.0 allows local users to bypass the 'strict page
    permissions' protection mechanism and modify the system-call table, and consequently gain privileges, by
    leveraging write access. (CVE-2015-8967)

  - The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel before 4.6.3 allows
    local users to gain privileges or cause a denial of service (stack memory consumption) via vectors
    involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling. (CVE-2016-1583)

  - In android for MSM, Firefox OS for MSM, QRD Android, with all Android releases from CAF using the Linux
    kernel, a buffer overread is observed in nl80211_set_station when user space application sends attribute
    NL80211_ATTR_LOCAL_MESH_POWER_MODE with data of size less than 4 bytes (CVE-2017-11089)

  - In all Qualcomm products with Android releases from CAF using the Linux kernel, during DMA allocation, due
    to wrong data type of size, allocation size gets truncated which makes allocation succeed when it should
    fail. (CVE-2017-9725)

  - A vulnerability was found in Linux Kernel where refcount leak in llcp_sock_bind() causing use-after-free
    which might lead to privilege escalations. (CVE-2020-25670)

  - A vulnerability was found in Linux Kernel, where a refcount leak in llcp_sock_connect() causing use-after-
    free which might lead to privilege escalations. (CVE-2020-25671)

  - A vulnerability was found in Linux kernel where non-blocking socket in llcp_sock_connect() leads to leak
    and eventually hanging-up the system. (CVE-2020-25673)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

  - There is a flaw reported in the Linux kernel in versions before 5.9 in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker with a local account with a root privilege, can leverage this vulnerability to
    escalate privileges and execute code in the context of the kernel. (CVE-2021-20292)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - A race condition was discovered in get_old_root in fs/btrfs/ctree.c in the Linux kernel through 5.11.8. It
    allows attackers to cause a denial of service (BUG) because of a lack of locking on an extent buffer
    before a cloning operation, aka CID-dbcc7d57bffc. (CVE-2021-28964)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - An issue was discovered in the Linux kernel before 5.11.7. usbip_sockfd_store in
    drivers/usb/usbip/stub_dev.c allows attackers to cause a denial of service (GPF) because the stub-up
    sequence has race conditions during an update of the local and shared status, aka CID-9380afd6df70.
    (CVE-2021-29265)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.
    (CVE-2021-3347)

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

  - A flaw was found in the Nosy driver in the Linux kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality, integrity, as well as system availability. Versions
    before kernel 5.12-rc6 are affected (CVE-2021-3483)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - A use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in the way
    user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call hci_unregister_dev()
    together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(), hci_get_conn_info(),
    hci_get_auth_info(). A privileged local user could use this flaw to crash the system or escalate their
    privileges on the system. This flaw affects the Linux kernel versions prior to 5.13-rc5. (CVE-2021-3573)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2588
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74bb9ae9");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9725");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-3.10.0-514.44.5.10.h339",
  "kernel-debuginfo-3.10.0-514.44.5.10.h339",
  "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h339",
  "kernel-devel-3.10.0-514.44.5.10.h339",
  "kernel-headers-3.10.0-514.44.5.10.h339",
  "kernel-tools-3.10.0-514.44.5.10.h339",
  "kernel-tools-libs-3.10.0-514.44.5.10.h339",
  "perf-3.10.0-514.44.5.10.h339",
  "python-perf-3.10.0-514.44.5.10.h339"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
