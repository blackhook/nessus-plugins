#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134735);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-5897",
    "CVE-2018-16871",
    "CVE-2018-16884",
    "CVE-2018-20856",
    "CVE-2018-20976",
    "CVE-2018-7191",
    "CVE-2019-12378",
    "CVE-2019-12381",
    "CVE-2019-14821",
    "CVE-2019-15538",
    "CVE-2019-15807",
    "CVE-2019-15921",
    "CVE-2019-16994",
    "CVE-2019-18805",
    "CVE-2019-19062",
    "CVE-2019-3882"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : kernel (EulerOS-SA-2020-1269)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - In the tun subsystem in the Linux kernel before
    4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a
    denial of service (NULL pointer dereference and panic)
    via an ioctl(TUNSETIFF) call with a dev name containing
    a / character. This is similar to
    CVE-2013-4343.(CVE-2018-7191)

  - A memory leak in the crypto_report() function in
    crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering crypto_report_alg()
    failures, aka CID-ffdde5932042.(CVE-2019-19062)

  - An issue was discovered in net/ipv4/sysctl_net_ipv4.c
    in the Linux kernel before 5.0.11. There is a
    net/ipv4/tcp_input.c signed integer overflow in
    tcp_ack_update_rtt() when userspace writes a very large
    integer to /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading
    to a denial of service or possibly unspecified other
    impact, aka CID-19fad20d15a6.(CVE-2019-18805)

  - In the Linux kernel before 5.0, a memory leak exists in
    sit_init_net() in net/ipv6/sit.c when register_netdev()
    fails to register sitn->fb_tunnel_dev, which may cause
    denial of service, aka
    CID-07f12b26e21a.(CVE-2019-16994)

  - An issue was discovered in the Linux kernel before
    5.0.6. There is a memory leak issue when idr_alloc()
    fails in genl_register_family() in
    net/netlink/genetlink.c.(CVE-2019-15921)

  - In the Linux kernel before 5.1.13, there is a memory
    leak in drivers/scsi/libsas/sas_expander.c when SAS
    expander discovery fails. This will cause a BUG and
    denial of service.(CVE-2019-15807)

  - An issue was discovered in xfs_setattr_nonsize in
    fs/xfs/xfs_iops.c in the Linux kernel through 5.2.9.
    XFS partially wedges when a chgrp fails on account of
    being out of disk quota. xfs_setattr_nonsize is failing
    to unlock the ILOCK after the xfs_qm_vop_chown_reserve
    call fails. This is primarily a local DoS attack
    vector, but it might result as well in remote DoS if
    the XFS filesystem is exported for instance via
    NFS.(CVE-2019-15538)

  - An out-of-bounds access issue was found in the Linux
    kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO
    write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write
    indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged
    host user or process with access to '/dev/kvm' device
    could use this flaw to crash the host kernel, resulting
    in a denial of service or potentially escalating
    privileges on the system.(CVE-2019-14821)

  - ** DISPUTED ** An issue was discovered in ip_ra_control
    in net/ipv4/ip_sockglue.c in the Linux kernel through
    5.1.5. There is an unchecked kmalloc of new_ra, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system crash). NOTE: this
    is disputed because new_ra is never used if it is
    NULL.(CVE-2019-12381)

  - ** DISPUTED ** An issue was discovered in
    ip6_ra_control in net/ipv6/ipv6_sockglue.c in the Linux
    kernel through 5.1.5. There is an unchecked kmalloc of
    new_ra, which might allow an attacker to cause a denial
    of service (NULL pointer dereference and system crash).
    NOTE: This has been disputed as not an
    issue.(CVE-2019-12378)

  - An issue was discovered in fs/xfs/xfs_super.c in the
    Linux kernel before 4.18. A use after free exists,
    related to xfs_fs_fill_super failure.(CVE-2018-20976)

  - An issue was discovered in the Linux kernel before
    4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain
    error case is mishandled.(CVE-2018-20856)

  - A flaw was found in the Linux kernel's NFS41+
    subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process()
    use wrong back-channel IDs and cause a use-after-free
    vulnerability. Thus a malicious container user can
    cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out.(CVE-2018-16884)

  - A flaw was found in the Linux kernel's NFS
    implementation, all versions 3.x and all versions 4.x
    up to 4.20. An attacker, who is able to mount an
    exported NFS filesystem, is able to trigger a null
    pointer dereference by using an invalid NFS sequence.
    This can panic the machine and deny access to the NFS
    server. Any outstanding disk writes to the NFS server
    will be lost.(CVE-2018-16871)

  - An issue was found in the Linux kernel ipv6
    implementation of GRE tunnels which allows a remote
    attacker to trigger an out-of-bounds access. At this
    time we understand no trust barrier has been crossed
    and there is no security implications in this
    flaw.(CVE-2017-5897)

  - A flaw was found in the Linux kernel's vfio interface
    implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio
    driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it
    may cause a system memory exhaustion and thus a denial
    of service (DoS). Versions 3.10, 4.14 and 4.18 are
    vulnerable.(CVE-2019-3882)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1269
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed95715f");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18805");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_72",
        "kernel-devel-3.10.0-862.14.1.6_72",
        "kernel-headers-3.10.0-862.14.1.6_72",
        "kernel-tools-3.10.0-862.14.1.6_72",
        "kernel-tools-libs-3.10.0-862.14.1.6_72",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_72",
        "perf-3.10.0-862.14.1.6_72",
        "python-perf-3.10.0-862.14.1.6_72"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
