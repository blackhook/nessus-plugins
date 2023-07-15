#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124974);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4348",
    "CVE-2014-5045",
    "CVE-2014-5206",
    "CVE-2014-7825",
    "CVE-2014-8369",
    "CVE-2014-8989",
    "CVE-2015-8785",
    "CVE-2016-2059",
    "CVE-2016-2185",
    "CVE-2016-2188",
    "CVE-2016-3713",
    "CVE-2016-7039",
    "CVE-2017-13695",
    "CVE-2017-15649",
    "CVE-2017-15951",
    "CVE-2017-17805",
    "CVE-2017-6874",
    "CVE-2017-7895",
    "CVE-2018-13093",
    "CVE-2018-7492"
  );
  script_bugtraq_id(
    63536,
    68862,
    69214,
    70747,
    70749,
    70972,
    71154,
    71367
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1521)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The NFSv2 and NFSv3 server implementations in the Linux
    kernel through 4.10.13 lacked certain checks for the
    end of a buffer. A remote attacker could trigger a
    pointer-arithmetic error or possibly cause other
    unspecified impacts using crafted requests related to
    fs/nfsd/nfs3xdr.c and
    fs/nfsd/nfsxdr.c.(CVE-2017-7895i1/4%0

  - A flaw was found in the Linux kernel's ACPI subsystem
    where a function does not flush the operand cache and
    causes a kernel stack dump. This allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism when using a
    specially crafted ACPI table.(CVE-2017-13695i1/4%0

  - It was found that fanout_add() in
    'net/packet/af_packet.c' in the Linux kernel, before
    version 4.13.6, allows local users to gain privileges
    via crafted system calls that trigger mishandling of
    packet_fanout data structures, because of a race
    condition (involving fanout_add and packet_do_bind)
    that leads to a use-after-free bug.(CVE-2017-15649i1/4%0

  - Race condition in kernel/ucount.c in the Linux kernel
    through 4.10.2 allows local users to cause a denial of
    service (use-after-free and system crash) or possibly
    have unspecified other impact via crafted system calls
    that leverage certain decrement behavior that causes
    incorrect interaction between put_ucounts and
    get_ucounts.(CVE-2017-6874i1/4%0

  - An out-of-bounds memory access flaw, CVE-2014-7825, was
    found in the syscall tracing functionality of the Linux
    kernel's perf subsystem. A local, unprivileged user
    could use this flaw to crash the system. Additionally,
    an out-of-bounds memory access flaw, CVE-2014-7826, was
    found in the syscall tracing functionality of the Linux
    kernel's ftrace subsystem. On a system with ftrace
    syscall tracing enabled, a local, unprivileged user
    could use this flaw to crash the system, or escalate
    their privileges.(CVE-2014-7825i1/4%0

  - The Salsa20 encryption algorithm in the Linux kernel,
    before 4.14.8, does not correctly handle zero-length
    inputs. This allows a local attacker the ability to use
    the AF_ALG-based skcipher interface to cause a denial
    of service (uninitialized-memory free and kernel crash)
    or have an unspecified other impact by executing a
    crafted sequence of system calls that use the
    blkcipher_walk API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 are
    vulnerable.(CVE-2017-17805i1/4%0

  - The msm_ipc_router_bind_control_port function in
    net/ipc_router/ipc_router_core.c in the IPC router
    kernel module for the Linux kernel 3.x, as used in
    Qualcomm Innovation Center (QuIC) Android contributions
    for MSM devices and other products, does not verify
    that a port is a client port, which allows attackers to
    gain privileges or cause a denial of service (race
    condition and list corruption) by making many
    BIND_CONTROL_PORT ioctl calls.(CVE-2016-2059i1/4%0

  - The do_remount function in fs/namespace.c in the Linux
    kernel through 3.16.1 does not maintain the
    MNT_LOCK_READONLY bit across a remount of a bind mount,
    which allows local users to bypass an intended
    read-only restriction and defeat certain sandbox
    protection mechanisms via a 'mount -o remount' command
    within a user namespace.(CVE-2014-5206i1/4%0

  - The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-2185i1/4%0

  - It was found that the fix for CVE-2014-3601 was
    incomplete: the Linux kernel's kvm_iommu_map_pages()
    function still handled IOMMU mapping failures
    incorrectly. A privileged user in a guest with an
    assigned host device could use this flaw to crash the
    host.(CVE-2014-8369i1/4%0

  - A NULL pointer dereference was found in
    net/rds/rdma.c:__rds_rdma_map() function in the Linux
    kernel allowing local attackers to cause a system panic
    and a denial-of-service.(CVE-2018-7492i1/4%0

  - An issue was discovered in the XFS filesystem in
    fs/xfs/xfs_icache.c in the Linux kernel. There is a
    NULL pointer dereference leading to a system panic in
    lookup_slow() on a NULL inode-i1/4zi_ops pointer when
    doing pathwalks on a corrupted xfs image. This occurs
    because of a lack of proper validation that cached
    inodes are free during an allocation.(CVE-2018-13093i1/4%0

  - The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (NULL pointer dereference and system
    crash) via a crafted endpoints value in a USB device
    descriptor.(CVE-2016-2188i1/4%0

  - Linux kernel built with the 802.1Q/802.1ad
    VLAN(CONFIG_VLAN_8021Q) OR Virtual eXtensible Local
    Area Network(CONFIG_VXLAN) with Transparent Ethernet
    Bridging(TEB) GRO support, is vulnerable to a stack
    overflow issue. It could occur while receiving large
    packets via GRO path, as an unlimited recursion could
    unfold in both VLAN and TEB modules, leading to a stack
    corruption in the kernel.(CVE-2016-7039i1/4%0

  - The msr_mtrr_valid function in arch/x86/kvm/mtrr.c in
    the Linux kernel before 4.6.1 supports MSR 0x2f8, which
    allows guest OS users to read or write to the
    kvm_arch_vcpu data structure, and consequently obtain
    sensitive information or cause a denial of service
    (system crash), via a crafted ioctl
    call.(CVE-2016-3713i1/4%0

  - A flaw was found in the way the Linux kernel's VFS
    subsystem handled reference counting when performing
    unmount operations on symbolic links. A local,
    unprivileged user could use this flaw to exhaust all
    available memory on the system or, potentially, trigger
    a use-after-free error, resulting in a system crash or
    privilege escalation.(CVE-2014-5045i1/4%0

  - The KEYS subsystem in the Linux kernel before 4.13.10
    does not correctly synchronize the actions of updating
    versus finding a key in the 'negative' state to avoid a
    race condition, which allows local users to cause a
    denial of service or possibly have unspecified other
    impact via crafted system calls.(CVE-2017-15951i1/4%0

  - The skb_flow_dissect function in
    net/core/flow_dissector.c in the Linux kernel through
    3.12 allows remote attackers to cause a denial of
    service (infinite loop) via a small value in the IHL
    field of a packet with IPIP
    encapsulation.(CVE-2013-4348i1/4%0

  - The Linux kernel through 3.17.4 does not properly
    restrict dropping of supplemental group memberships in
    certain namespace scenarios, which allows local users
    to bypass intended file permissions by leveraging a
    POSIX ACL containing an entry for the group category
    that is more restrictive than the entry for the other
    category, aka a 'negative groups' issue, related to
    kernel/groups.c, kernel/uid16.c, and
    kernel/user_namespace.c.(CVE-2014-8989i1/4%0

  - An infinite-loop flaw was found in the kernel. When a
    local user calls the sys_writev syscall with a
    specially crafted sequence of iov structs, the
    fuse_fill_write_pages kernel function might never
    terminate, instead continuing in a tight loop. This
    process cannot be terminated and requires a
    reboot.(CVE-2015-8785i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1521
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1899f2b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.28-1.2.117",
        "kernel-devel-4.19.28-1.2.117",
        "kernel-headers-4.19.28-1.2.117",
        "kernel-tools-4.19.28-1.2.117",
        "kernel-tools-libs-4.19.28-1.2.117",
        "kernel-tools-libs-devel-4.19.28-1.2.117",
        "perf-4.19.28-1.2.117",
        "python-perf-4.19.28-1.2.117"];

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
