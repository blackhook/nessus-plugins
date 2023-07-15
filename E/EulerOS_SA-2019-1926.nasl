#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128929);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/20");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2018-20855",
    "CVE-2018-20856",
    "CVE-2019-10639",
    "CVE-2019-12378",
    "CVE-2019-12380",
    "CVE-2019-12381",
    "CVE-2019-12456",
    "CVE-2019-12818",
    "CVE-2019-12819",
    "CVE-2019-12984",
    "CVE-2019-13272",
    "CVE-2019-13631",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14284",
    "CVE-2019-14763",
    "CVE-2019-15211",
    "CVE-2019-15292",
    "CVE-2019-16994"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2019-1926)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc. Security Fix(es):A flaw was found in the
    Linux kernel's NFS implementation, all versions 3.x and
    all versions 4.x up to 4.20. An attacker, who is able
    to mount an exported NFS filesystem, is able to trigger
    a null pointer dereference by using an invalid NFS
    sequence. This can panic the machine and deny access to
    the NFS server. Any outstanding disk writes to the NFS
    server will be lost.(CVE-2018-16871)An issue was
    discovered in the Linux kernel before 4.18.7. In
    create_qp_common in drivers/infiniband/hw/mlx5/qp.c,
    mlx5_ib_create_qp_resp was never initialized, resulting
    in a leak of stack memory to
    userspace.(CVE-2018-20855)An issue was discovered in
    the Linux kernel before 4.18.7. In block/blk-core.c,
    there is an __blk_drain_queue() use-after-free because
    a certain error case is mishandled.(CVE-2018-20856)The
    Linux kernel 4.x (starting from 4.1) and 5.x before
    5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass.
    Specifically, it is possible to extract the KASLR
    kernel image offset using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a
    static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is
    exposed. This attack can be carried out remotely, by
    the attacker forcing the target device to send UDP or
    ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is
    trivial if the server is a DNS server. ICMP traffic is
    trivial if the server answers ICMP Echo requests
    (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used
    to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became
    viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a
    network namespace.(CVE-2019-10639)** DISPUTED ** An
    issue was discovered in ip6_ra_control in
    net/ipv6/ipv6_sockglue.c in the Linux kernel through
    5.1.5. There is an unchecked kmalloc of new_ra, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system crash). NOTE: This
    has been disputed as not an
    issue.(CVE-2019-12378)**DISPUTED** An issue was
    discovered in the efi subsystem in the Linux kernel
    through 5.1.5. phys_efi_set_virtual_address_map in
    arch/x86/platform/efi/efi.c and efi_call_phys_prolog in
    arch/x86/platform/efi/efi_64.c mishandle memory
    allocation failures. NOTE: This id is disputed as not
    being an issue because ?All the code touched by the
    referenced commit runs only at boot, before any user
    processes are started. Therefore, there is no
    possibility for an unprivileged user to control
    it.?.(CVE-2019-12380)** DISPUTED ** An issue was
    discovered in ip_ra_control in net/ipv4/ip_sockglue.c
    in the Linux kernel through 5.1.5. There is an
    unchecked kmalloc of new_ra, which might allow an
    attacker to cause a denial of service (NULL pointer
    dereference and system crash). NOTE: this is disputed
    because new_ra is never used if it is
    NULL.(CVE-2019-12381)** DISPUTED ** An issue was
    discovered in the MPT3COMMAND case in _ctl_ioctl_main
    in drivers/scsi/mpt3sas/mpt3sas_ctl.c in the Linux
    kernel through 5.1.5. It allows local users to cause a
    denial of service or possibly have unspecified other
    impact by changing the value of ioc_number between two
    kernel reads of that value, aka a 'double fetch'
    vulnerability. NOTE: a third party reports that this is
    unexploitable because the doubly fetched value is not
    used.(CVE-2019-12456)An issue was discovered in the
    Linux kernel before 4.20.15. The nfc_llcp_build_tlv
    function in netfc/llcp_commands.c may return NULL. If
    the caller does not check for this, it will trigger a
    NULL pointer dereference. This will cause denial of
    service. This affects nfc_llcp_build_gb in
    netfc/llcp_core.c.(CVE-2019-12818)An issue was
    discovered in the Linux kernel before 5.0. The function
    __mdiobus_register() in driverset/phy/mdio_bus.c calls
    put_device(), which will trigger a fixed_mdio_bus_init
    use-after-free. This will cause a denial of
    service.(CVE-2019-12819)A NULL pointer dereference
    vulnerability in the function
    nfc_genl_deactivate_target() in netfcetlink.c in the
    Linux kernel before 5.1.13 can be triggered by a
    malicious user-mode program that omits certain NFC
    attributes, leading to denial of
    service.(CVE-2019-12984)In the Linux kernel before
    5.1.17, ptrace_link in kernel/ptrace.c mishandles the
    recording of the credentials of a process that wants to
    create a ptrace relationship, which allows local users
    to obtain root access by leveraging certain scenarios
    with a parent-child process relationship, where a
    parent drops privileges and calls execve (potentially
    allowing control by an attacker). One contributing
    factor is an object lifetime issue (which can also
    cause a panic). Another contributing factor is
    incorrect marking of a ptrace relationship as
    privileged, which is exploitable through (for example)
    Polkit's pkexec helper with PTRACE_TRACEME. NOTE:
    SELinux deny_ptrace might be a usable workaround in
    some environments.(CVE-2019-13272)In
    parse_hid_report_descriptor in
    drivers/input/tablet/gtco.c in the Linux kernel through
    5.2.1, a malicious USB device can send an HID report
    that triggers an out-of-bounds write during generation
    of debugging messages.(CVE-2019-13631)In the Linux
    kernel through 5.2.1 on the powerpc platform, when
    hardware transactional memory is disabled, a local user
    can cause a denial of service (TM Bad Thing exception
    and system crash) via a sigreturn() system call that
    sends a crafted signal frame. This affects
    arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c.(CVE-2019-13648)In the
    Linux kernel before 5.2.3, set_geometry in
    drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and
    out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been
    inserted. NOTE: QEMU creates the floppy device by
    default.(CVE-2019-14283)In the Linux kernel before
    5.2.3, drivers/block/floppy.c allows a denial of
    service by setup_format_params division-by-zero. Two
    consecutive ioctls can trigger the bug: the first one
    should set the drive geometry with .sect and .rate
    values that make F_SECT_PER_TRACK be zero. Next, the
    floppy format operation should be called. It can be
    triggered by an unprivileged local user even when a
    floppy disk has not been inserted. NOTE: QEMU creates
    the floppy device by default.(CVE-2019-14284)In the
    Linux kernel before 4.16.4, a double-locking error in
    drivers/usb/dwc3/gadget.c may potentially cause a
    deadlock with f_hid.(CVE-2019-14763)An issue was
    discovered in the Linux kernel before 5.2.6. There is a
    use-after-free caused by a malicious USB device in the
    drivers/media/v4l2-core/v4l2-dev.c driver because
    drivers/media/radio/radio-raremono.c does not properly
    allocate memory.(CVE-2019-15211)An issue was discovered
    in the Linux kernel before 5.0.9. There is a
    use-after-free in atalk_proc_exit, related to
    net/appletalk/atalk_proc.c, net/appletalk/ddp.c, and
    net/appletalk/sysctl_net_atalk.c.(CVE-2019-15292)A flaw
    was found in the way the sit_init_net function in the
    Linux kernel handled resource cleanup on errors. This
    flaw allows an attacker to use the error conditions to
    crash the system.(CVE-2019-16994)Note:
    kernel-4.19.36-vhulk1907.1.0.h529 and earlier versions
    in EulerOS Virtualization for ARM 64 3.0.2.0 return
    incorrect time information when executing the uname -a
    command.

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1926
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f4a8b79");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h420",
        "kernel-devel-4.19.36-vhulk1907.1.0.h420",
        "kernel-headers-4.19.36-vhulk1907.1.0.h420",
        "kernel-tools-4.19.36-vhulk1907.1.0.h420",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h420",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h420",
        "perf-4.19.36-vhulk1907.1.0.h420",
        "python-perf-4.19.36-vhulk1907.1.0.h420"];

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
