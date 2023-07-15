#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151562);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/15");

  script_cve_id(
    "CVE-2019-16089",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-36311",
    "CVE-2020-36312",
    "CVE-2021-23134",
    "CVE-2021-28950",
    "CVE-2021-29155",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33200",
    "CVE-2021-3444",
    "CVE-2021-3506"
  );

  script_name(english:"EulerOS Virtualization 2.9.1 : kernel (EulerOS-SA-2021-2183)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An issue was discovered in fs/fuse/fuse_i.h in the
    Linux kernel before 5.11.8. A 'stall on CPU' can occur
    because a retry loop continually finds the same bad
    inode, aka CID-775c5033a0d1.(CVE-2021-28950)

  - An issue was discovered in the Linux kernel before
    5.8.10. virt/kvm/kvm_main.c has a
    kvm_io_bus_unregister_dev memory leak upon a kmalloc
    failure, aka CID-f65886606c2d.(CVE-2020-36312)

  - An issue was discovered in the Linux kernel before 5.9.
    arch/x86/kvm/svm/sev.c allows attackers to cause a
    denial of service (soft lockup) by triggering
    destruction of a large SEV VM (which requires
    unregistering many encrypted regions), aka
    CID-7be74942f184.(CVE-2020-36311)

  - An out-of-bounds (OOB) memory access flaw was found in
    fs/f2fs/node.c in the f2fs module in the Linux kernel
    in versions before 5.12.0-rc4. A bounds check failure
    allows a local attacker to gain access to out-of-bounds
    memory leading to a system crash or a leak of internal
    kernel information. The highest threat from this
    vulnerability is to system availability.(CVE-2021-3506)

  - An out-of-bounds (OOB) memory write flaw was found in
    list_devices in drivers/md/dm-ioctl.c in the
    Multi-device driver module in the Linux kernel before
    5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access
    to out-of-bounds memory leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to system
    availability.(CVE-2021-31916)

  - An issue was discovered in the Linux kernel through
    5.2.13. nbd_genl_status in drivers/block/nbd.c does not
    check the nla_nest_start_noflag return
    value.(CVE-2019-16089)

  - The bpf verifier in the Linux kernel did not properly
    handle mod32 destination register truncation when the
    source register was known to be 0. A local attacker
    with the ability to load bpf programs could use this
    gain out-of-bounds reads in kernel memory leading to
    information disclosure (kernel memory), and possibly
    out-of-bounds writes that could potentially lead to
    code execution. This issue was addressed in the
    upstream kernel in commit 9b00f1b78809 ('bpf: Fix
    truncation handling for mod32 dst reg wrt zero') and in
    Linux stable kernels 5.11.2, 5.10.19, and
    5.4.101.(CVE-2021-3444)

  - An issue was discovered in the Linux kernel through
    5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic,
    leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from
    kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification
    performed by the first operation is not correctly
    accounted for when restricting subsequent
    operations.(CVE-2021-29155)

  - kernel/bpf/verifier.c in the Linux kernel through
    5.12.1 performs undesirable speculative loads, leading
    to disclosure of stack content via side-channel
    attacks, aka CID-801c6058d14a. The specific concern is
    not protecting the BPF stack area against speculative
    loads. Also, the BPF stack can contain uninitialized
    data that might represent sensitive information
    previously operated on by the kernel.(CVE-2021-31829)

  - net/bluetooth/hci_request.c in the Linux kernel through
    5.12.2 has a race condition for removal of the HCI
    controller.(CVE-2021-32399)

  - In the Linux kernel before 5.12.4,
    net/bluetooth/hci_event.c has a use-after-free when
    destroying an hci_chan, aka CID-5c4c8c954409. This
    leads to writing an arbitrary value.(CVE-2021-33034)

  - The Linux kernel before 5.11.14 has a use-after-free in
    cipso_v4_genopt in net/ipv4/cipso_ipv4.c because the
    CIPSO and CALIPSO refcounting for the DOI definitions
    is mishandled, aka CID-ad5d07f4a9cd. This leads to
    writing an arbitrary value.(CVE-2021-33033)

  - Use After Free vulnerability in nfc sockets in the
    Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations,
    the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability.(CVE-2021-23134)

  - A memory leak vulnerability was found in Linux kernel
    in llcp_sock_connect(CVE-2020-25672)

  - A vulnerability was found in Linux Kernel, where a
    refcount leak in llcp_sock_connect() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25671)

  - A vulnerability was found in Linux Kernel where
    refcount leak in llcp_sock_bind() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25670)

  - kernel/bpf/verifier.c in the Linux kernel through
    5.12.7 enforces incorrect limits for pointer arithmetic
    operations, aka CID-bb01a1bba579. This can be abused to
    perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation to root.
    In particular, there is a corner case where the off reg
    causes a masking direction change, which then results
    in an incorrect final aux->alu_limit.(CVE-2021-33200)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2183
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e73babb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-4.19.90-vhulk2103.1.0.h487.eulerosv2r9",
        "kernel-tools-4.19.90-vhulk2103.1.0.h487.eulerosv2r9",
        "kernel-tools-libs-4.19.90-vhulk2103.1.0.h487.eulerosv2r9",
        "perf-4.19.90-vhulk2103.1.0.h487.eulerosv2r9"];

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
