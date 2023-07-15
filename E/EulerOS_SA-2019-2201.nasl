#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130663);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-10853",
    "CVE-2018-1128",
    "CVE-2018-20976",
    "CVE-2018-7492",
    "CVE-2019-10140",
    "CVE-2019-10142",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-1125",
    "CVE-2019-12818",
    "CVE-2019-14814",
    "CVE-2019-14815",
    "CVE-2019-14816",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15098",
    "CVE-2019-15099",
    "CVE-2019-15118",
    "CVE-2019-15218",
    "CVE-2019-15219",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15239",
    "CVE-2019-15292",
    "CVE-2019-15505",
    "CVE-2019-15538",
    "CVE-2019-15807",
    "CVE-2019-15921",
    "CVE-2019-15924",
    "CVE-2019-15926",
    "CVE-2019-15927",
    "CVE-2019-16233",
    "CVE-2019-16413",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-2201)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):An issue was discovered in
    the Linux kernel before 5.2.3. Out of bounds access
    exists in the functions
    ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    driverset/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)An
    issue was discovered in the Linux kernel before 5.0.6.
    There is a memory leak issue when idr_alloc() fails in
    genl_register_family() in
    netetlink/genetlink.c.(CVE-2019-15921)An issue was
    discovered in the Linux kernel before 4.20.2. An
    out-of-bounds access exists in the function
    build_audio_procunit in the file
    sound/usb/mixer.c.(CVE-2019-15927)An issue was
    discovered in the Linux kernel before 5.0.9. There is a
    use-after-free in atalk_proc_exit, related to
    net/appletalk/atalk_proc.c, net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c.(CVE-2019-15292)An
    issue was discovered in fs/xfs/xfs_super.c in the Linux
    kernel before 4.18. A use after free exists, related to
    xfs_fs_fill_super failure.(CVE-2018-20976)In the Linux
    kernel before 5.1.13, there is a memory leak in
    drivers/scsi/libsas/sas_expander.c when SAS expander
    discovery fails. This will cause a BUG and denial of
    service.(CVE-2019-15807)A vulnerability was found in
    Linux kernel's, versions up to 3.10, implementation of
    overlayfs. An attacker with local access can create a
    denial of service situation via NULL pointer
    dereference in ovl_posix_acl_create function in
    fs/overlayfs/dir.c. This can allow attackers with
    ability to create directories on overlayfs to crash the
    kernel creating a denial of service
    (DOS).(CVE-2019-10140)In the Linux kernel, a certain
    net/ipv4/tcp_output.c change, which was properly
    incorporated into 4.16.12, was incorrectly backported
    to the earlier longterm kernels, introducing a new
    vulnerability that was potentially more severe than the
    issue that was intended to be fixed by backporting.
    Specifically, by adding to a write queue between
    disconnection and re-connection, a local attacker can
    trigger multiple use-after-free conditions. This can
    result in a kernel crash, or potentially in privilege
    escalation.(CVE-2019-15239)check_input_term in
    sound/usb/mixer.c in the Linux kernel through 5.2.9
    mishandles recursion, leading to kernel stack
    exhaustion.(CVE-2019-15118)drivers
    et/wireless/ath/ath10k/usb.c in the Linux kernel
    through 5.2.8 has a NULL pointer dereference via an
    incomplete address in an endpoint
    descriptor.(CVE-2019-15099)drivers
    et/wireless/ath/ath6kl/usb.c in the Linux kernel
    through 5.2.9 has a NULL pointer dereference via an
    incomplete address in an endpoint
    descriptor.(CVE-2019-15098)A flaw was found in the
    Linux kernel's Bluetooth implementation of UART. An
    attacker with local access and write permissions to the
    Bluetooth hardware could use this flaw to issue a
    specially crafted ioctl function call and cause the
    system to crash.(CVE-2019-10207)It was found that cephx
    authentication protocol did not verify ceph clients
    correctly and was vulnerable to replay attack. Any
    attacker having access to ceph cluster network who is
    able to sniff packets on network can use this
    vulnerability to authenticate with ceph service and
    perform actions allowed by ceph service. Ceph branches
    master, mimic, luminous and jewel are believed to be
    vulnerable.(CVE-2018-1128)ax25_create in
    net/ax25/af_ax25.c in the AF_AX25 network module in the
    Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-0614e2b73768.(CVE-2019-17052)ieee802154_create in
    net/ieee802154/socket.c in the AF_IEEE802154 network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-e69dbd4619e7.(CVE-2019-17053)atalk_create in
    net/appletalk/ddp.c in the AF_APPLETALK network module
    in the Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-6cc03e8aa36c.(CVE-2019-17054)base_sock_create in
    drivers/isdn/mISDN/socket.c in the AF_ISDN network
    module in the Linux kernel through 5.3.2 does not
    enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-b91ee4aa2a21.(CVE-2019-17055)llcp_sock_create in
    net fc/llcp_sock.c in the AF_NFC network module in the
    Linux kernel through 5.3.2 does not enforce
    CAP_NET_RAW, which means that unprivileged users can
    create a raw socket, aka
    CID-3a359798b176.(CVE-2019-17056)A flaw was found in
    the Linux kernel's freescale hypervisor manager
    implementation, kernel versions 5.0.x up to, excluding
    5.0.17. A parameter passed to an ioctl was incorrectly
    validated and used in size calculations for the page
    size calculation. An attacker can use this flaw to
    crash the system, corrupt memory, or create other
    adverse security
    affects.(CVE-2019-10142)drivers/media/usb/dvb-usb/techn
    isat-usb2.c in the Linux kernel through 5.2.9 has an
    out-of-bounds read via crafted USB device traffic
    (which may be remote via usbip or
    usbredir).(CVE-2019-15505)An issue was discovered in
    the Linux kernel before 5.0.4. The 9p filesystem did
    not protect i_size_write() properly, which causes an
    i_size_read() infinite loop and denial of service on
    SMP systems.(CVE-2019-16413)An issue was discovered in
    xfs_setattr_nonsize in fs/xfs/xfs_iops.c in the Linux
    kernel through 5.2.9. XFS partially wedges when a chgrp
    fails on account of being out of disk quota.
    xfs_setattr_nonsize is failing to unlock the ILOCK
    after the xfs_qm_vop_chown_reserve call fails. This is
    primarily a local DoS attack vector, but it might
    result as well in remote DoS if the XFS filesystem is
    exported for instance via NFS.(CVE-2019-15538)A buffer
    overflow flaw was found, in versions from 2.6.34 to
    5.2.x, in the way Linux kernel's vhost functionality
    that translates virtqueue buffers to IOVs, logged the
    buffer descriptors during migration. A privileged guest
    user able to pass descriptors with invalid length to
    the host when migration is underway, could use this
    flaw to increase their privileges on the
    host.(CVE-2019-14835)An out-of-bounds access issue was
    found in the Linux kernel, all versions through 5.3, in
    the way Linux kernel's KVM hypervisor implements the
    Coalesced MMIO write operation. It operates on an MMIO
    ring buffer 'struct kvm_coalesced_mmio' object, wherein
    write indices 'ring->first' and 'ring->last' value
    could be supplied by a host user-space process. An
    unprivileged host user or process with access to
    '/dev/kvm' device could use this flaw to crash the host
    kernel, resulting in a denial of service or potentially
    escalating privileges on the system.(CVE-2019-14821)An
    information disclosure vulnerability exists when
    certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information
    Disclosure Vulnerability'.
    (CVE-2019-1125)drivers/scsi/qla2xxx/qla_os.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16233)An issue was discovered in
    the Linux kernel before 5.0.11. fm10k_init_module in
    drivers et/ethernet/intel/fm10k/fm10k_main.c has a NULL
    pointer dereference because there is no -ENOMEM upon an
    alloc_workqueue failure.(CVE-2019-15924)An issue was
    discovered in the Linux kernel before 5.2.1. There is a
    use-after-free caused by a malicious USB device in the
    drivers et/wireless/intersil/p54/p54usb.c
    driver.(CVE-2019-15220 )In the Linux kernel before
    5.1.7, a device can be tracked by an attacker using the
    IP ID values the kernel produces for connection-less
    protocols (e.g., UDP and ICMP). When such traffic is
    sent to multiple destination IP addresses, it is
    possible to obtain hash collisions (of indices to the
    counter array) and thereby obtain the hashing key (via
    enumeration). An attack may be conducted by hosting a
    crafted web page that uses WebRTC or gQUIC to force UDP
    traffic to attacker-controlled IP
    addresses.(CVE-2019-10638)There is heap-based buffer
    overflow in Linux kernel, all versions up to, excluding
    5.3, in the marvell wifi chip driver in Linux kernel,
    that allows local users to cause a denial of
    service(system crash) or possibly execute arbitrary
    code.( CVE-2019-14814)** RESERVED ** This candidate has
    been reserved by an organization or individual that
    will use it when announcing a new security problem.
    When the candidate has been publicized, the details for
    this candidate will be provided.( CVE-2019-14815)There
    is heap-based buffer overflow in kernel, all versions
    up to, excluding 5.3, in the marvell wifi chip driver
    in Linux kernel, that allows local users to cause a
    denial of service(system crash) or possibly execute
    arbitrary code.( CVE-2019-14816)A flaw was found in the
    way Linux kernel KVM hypervisor emulated instructions
    such as sgdt/sidt/fxsave/fxrstor. It did not check
    current privilege(CPL) level while emulating
    unprivileged instructions. An unprivileged guest
    user/process could use this flaw to potentially
    escalate privileges inside guest.(CVE-2018-10853)A NULL
    pointer dereference was found in the net/rds/rdma.c
    __rds_rdma_map() function in the Linux kernel before
    4.14.7 allowing local attackers to cause a system panic
    and a denial-of-service, related to RDS_GET_MR and
    RDS_GET_MR_FOR_DEST.(CVE-2018-7492)An issue was
    discovered in the Linux kernel before 4.20.15. The
    nfc_llcp_build_tlv function in net fc/llcp_commands.c
    may return NULL. If the caller does not check for this,
    it will trigger a NULL pointer dereference. This will
    cause denial of service. This affects nfc_llcp_build_gb
    in netfc/llcp_core.c.(CVE-2019-12818)An issue was
    discovered in the Linux kernel before 5.1.8. There is a
    NULL pointer dereference caused by a malicious USB
    device in the drivers/media/usb/siano/smsusb.c
    driver.(CVE-2019-15218)An issue was discovered in the
    Linux kernel before 5.1.8. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/sisusbvga/sisusb.c
    driver.(CVE-2019-15219)An issue was discovered in the
    Linux kernel before 5.1.17. There is a NULL pointer
    dereference caused by a malicious USB device in the
    sound/usb/line6/pcm.c driver.(CVE-2019-15221)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3a7512b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "perf-3.10.0-862.14.1.2.h291.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.2.h291.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
