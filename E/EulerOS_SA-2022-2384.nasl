#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165388);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id(
    "CVE-2020-36558",
    "CVE-2021-33655",
    "CVE-2021-33656",
    "CVE-2022-0494",
    "CVE-2022-0854",
    "CVE-2022-1012",
    "CVE-2022-1280",
    "CVE-2022-1353",
    "CVE-2022-1729",
    "CVE-2022-1789",
    "CVE-2022-2153",
    "CVE-2022-20132",
    "CVE-2022-20154",
    "CVE-2022-20166",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23037",
    "CVE-2022-26365",
    "CVE-2022-28388",
    "CVE-2022-28390",
    "CVE-2022-29581",
    "CVE-2022-30594",
    "CVE-2022-32296",
    "CVE-2022-33740",
    "CVE-2022-33741",
    "CVE-2022-33742",
    "CVE-2022-34918"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : kernel (EulerOS-SA-2022-2384)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A race condition in the Linux kernel before 5.5.7 involving VT_RESIZEX could lead to a NULL pointer
    dereference and general protection fault. (CVE-2020-36558)

  - When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of
    bounds. (CVE-2021-33655)

  - When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.
    (CVE-2021-33656)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

  - Due to the small table perturb size, a memory leak flaw was found in the Linux kernel's TCP source port
    generation algorithm in the net/ipv4/tcp.c function. This flaw allows an attacker to leak information and
    may cause a denial of service. (CVE-2022-1012)

  - A use-after-free vulnerability was found in drm_lease_held in drivers/gpu/drm/drm_lease.c in the Linux
    kernel due to a race problem. This flaw allows a local user privilege attacker to cause a denial of
    service (DoS) or a kernel information leak. (CVE-2022-1280)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel.This flaw
    allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a leak of
    internal kernel information. (CVE-2022-1353)

  - Kernel-headers includes the C header files that specify the interfacebetween the Linux kernel and
    userspace libraries and programs.  Theheader files define structures and constants that are needed
    forbuilding most standard programs and are also needed for rebuilding theglibc package. (CVE-2022-1729)

  - With shadow paging enabled, the INVPCID instruction results in a call to kvm_mmu_invpcid_gva. If INVPCID
    is executed with CR0.PG=0, the invlpg callback is not set and the result is a NULL pointer dereference.
    (CVE-2022-1789)

  - In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds
    read due to improper input validation. This could lead to local information disclosure if a malicious USB
    HID device were plugged in, with no additional execution privileges needed. User interaction is not needed
    for exploitation. (CVE-2022-20132)

  - In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead
    to local escalation of privilege with System execution privileges needed. User interaction is not needed
    for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream
    kernel (CVE-2022-20154)

  - In various methods of kernel base drivers, there is a possible out of bounds write due to a heap buffer
    overflow. This could lead to local escalation of privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-182388481References: Upstream kernel (CVE-2022-20166)

  - Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via local access. (CVE-2022-21123)

  - Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21125)

  - Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2022-21166)

  - A flaw was found in the Linux kernel's KVM when attempting to set a SynIC IRQ. This issue makes it
    possible for a misbehaving VMM to write to SYNIC/STIMER MSRs, causing a NULL pointer dereference. This
    flaw allows an unprivileged local attacker on the host to issue specific ioctl calls, causing a kernel
    oops condition that results in a denial of service. (CVE-2022-2153)

  - Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV
    device frontends are using the grant table interfaces for removing access rights of the backends in ways
    being subject to race conditions, resulting in potential data leaks, data corruption by malicious
    backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the
    gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they
    assume that a following removal of the granted access will always succeed, which is not true in case the
    backend has mapped the granted page between those two operations. As a result the backend can keep access
    to the memory page of the guest no matter how the page will be used after the frontend I/O has finished.
    The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of
    a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038
    gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus,
    9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no
    longer in use, but the freeing of the related data page is not synchronized with dropping the granted
    access. As a result the backend can keep access to the memory page even after it has been freed and then
    re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to
    revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which
    can be triggered by the backend. CVE-2022-23042 (CVE-2022-23037)

  - Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text
    explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device
    frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740).
    Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to
    unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend
    (CVE-2022-33741, CVE-2022-33742). (CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to
    cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14
    and later versions. (CVE-2022-29581)

  - The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers
    to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag. (CVE-2022-30594)

  - The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are
    used. (CVE-2022-32296)

  - An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init
    (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different
    vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an
    unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data
    in net/netfilter/nf_tables_api.c. (CVE-2022-34918)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1339d9d4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-4.18.0-147.5.1.6.h806.eulerosv2r9",
  "kernel-tools-4.18.0-147.5.1.6.h806.eulerosv2r9",
  "kernel-tools-libs-4.18.0-147.5.1.6.h806.eulerosv2r9",
  "python3-perf-4.18.0-147.5.1.6.h806.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
