#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135129);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-11135",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-19332",
    "CVE-2019-19338",
    "CVE-2019-19922",
    "CVE-2019-19947",
    "CVE-2019-20095",
    "CVE-2019-20096",
    "CVE-2019-3016",
    "CVE-2019-5108",
    "CVE-2020-8428",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-9383"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : kernel (EulerOS-SA-2020-1342)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A heap-based buffer overflow was discovered in the
    Linux kernel's Marvell WiFi chip driver. The flaw could
    occur when the station attempts a connection
    negotiation during the handling of the remote devices
    country settings. This could allow the remote device to
    cause a denial of service (system crash) or possibly
    execute arbitrary code.(CVE-2019-14895)

  - A flaw was found in the fix for CVE-2019-11135, the way
    Intel CPUs handle speculative execution of instructions
    when a TSX Asynchronous Abort (TAA) error occurs. When
    a guest is running on a host CPU affected by the TAA
    flaw (TAA_NO=0), but is not affected by the MDS issue
    (MDS_NO=1), the guest was to clear the affected buffers
    by using a VERW instruction mechanism. But when the
    MDS_NO=1 bit was exported to the guests, the guests did
    not use the VERW mechanism to clear the affected
    buffers. This issue affects guests running on Cascade
    Lake CPUs and requires that host has 'TSX' enabled.
    Confidentiality of data is the highest threat
    associated with this vulnerability.(CVE-2019-19338)

  - A flaw was found in the way Intel CPUs handle
    speculative execution of instructions when the TSX
    Asynchronous Abort (TAA) error occurs. A local
    authenticated attacker with the ability to monitor
    execution times could infer the TSX memory state by
    comparing abort execution times. This could allow
    information disclosure via this observed side-channel
    for any TSX transaction being executed while an
    attacker is able to observe abort timing. Intel's
    Transactional Synchronisation Extensions (TSX) are set
    of instructions which enable transactional memory
    support to improve performance of the multi-threaded
    applications, in the lock-protected critical sections.
    The CPU executes instructions in the critical-sections
    as transactions, while ensuring their atomic state.
    When such transaction execution is unsuccessful, the
    processor cannot ensure atomic updates to the
    transaction memory, so the processor rolls back or
    aborts such transaction execution. While TSX
    Asynchronous Abort (TAA) is pending, CPU may continue
    to read data from architectural buffers and pass it to
    the dependent speculative operations. This may cause
    information leakage via speculative side-channel means,
    which is quite similar to the Microarchitectural Data
    Sampling (MDS) issue.(CVE-2019-11135)

  - An out-of-bounds memory write issue was found in the
    way the Linux kernel's KVM hypervisor handled the
    'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or
    process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of
    service.(CVE-2019-19332)

  - A flaw was found in the Linux kernel's scheduler, where
    it can allow attackers to cause a denial of service
    against non-CPU-bound applications by generating a
    workload that triggers unwanted scheduling slice
    expiration. A local attacker who can trigger a specific
    workload type could abuse this technique to trigger a
    system to be seen as degraded, and possibly trigger
    workload-rebalance in systems that use the
    slice-expiration metric as a measure of system
    health.(CVE-2019-19922)

  - A stack-based buffer overflow was found in the Linux
    kernel's Marvell WiFi chip driver. An attacker is able
    to cause a denial of service (system crash) or,
    possibly execute arbitrary code, when a STA works in
    IBSS mode (allows connecting stations together without
    the use of an AP) and connects to another
    STA.(CVE-2019-14897)

  - A heap-based buffer overflow vulnerability was found in
    the Linux kernel's Marvell WiFi chip driver. A remote
    attacker could cause a denial of service (system crash)
    or, possibly execute arbitrary code, when the
    lbs_ibss_join_existing function is called after a STA
    connects to an AP.(CVE-2019-14896)

  - A flaw was found in the Linux kernel in versions
    through 5.4.6, containing information leaks of
    uninitialized memory to a USB device. The latest
    findings show that the uninitialized memory allocation
    was not leading to an information leak, but was
    allocating the memory assigned with data on the next
    line and hence causing no violation..(CVE-2019-19947)

  - A flaw was found in the Linux kernel's implementation
    of the Datagram Congestion Control Protocol (DCCP). A
    local attacker with access to the system can create
    DCCP sockets to cause a memory leak and repeat this
    operation to exhaust all memory and panic the
    system.(CVE-2019-20096)

  - A flaw was found in the Linux kernel's mwifiex driver
    implementation when connecting to other WiFi devices in
    'Test Mode.' A kernel memory leak can occur if an error
    condition is met during the parameter negotiation. This
    issue can lead to a denial of service if multiple error
    conditions meeting the repeated connection attempts are
    attempted.(CVE-2019-20095)

  - A flaw was found in the Linux kernel's implementation
    of the WiFi station handoff code. An attacker within
    the radio range could use this flaw to deny a valid
    device from joining the access point.(CVE-2019-5108)

  - A flaw was found in the way Linux kernel's KVM
    hypervisor handled deferred TLB flush requests from
    guest. A race condition may occur between the guest
    issuing a deferred TLB flush request to KVM, and then
    KVM handling and acknowledging it. This may result in
    invalid address translations from TLB being used to
    access guest memory, leading to a potential information
    leakage issue. An attacker may use this flaw to access
    guest memory locations that it should not have access
    to.(CVE-2019-3016)

  - fs/namei.c in the Linux kernel before 5.5 has a
    may_create_in_sticky use-after-free, which allows local
    users to cause a denial of service (OOPS) or possibly
    obtain sensitive information from kernel memory, aka
    CID-d0cb50185ae9. One attack vector may be an open
    system call for a UNIX domain socket, if the socket is
    being moved to a new parent directory and its old
    parent directory is being removed.(CVE-2020-8428)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c.(CVE-2020-8648)

  - An issue was discovered in the Linux kernel through
    5.5.6. set_fdc in drivers/block/floppy.c leads to a
    wait_til_ready out-of-bounds read because the FDC index
    is not checked for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vgacon_invert_region
    function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1342
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ae277fb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h697.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h697.eulerosv2r8"];

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
