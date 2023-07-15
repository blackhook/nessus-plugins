#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124811);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2015-1805",
    "CVE-2015-2041",
    "CVE-2015-2042",
    "CVE-2015-2150",
    "CVE-2015-2666",
    "CVE-2015-2672",
    "CVE-2015-2830",
    "CVE-2015-2922",
    "CVE-2015-2925",
    "CVE-2015-3212",
    "CVE-2015-3288",
    "CVE-2015-3290",
    "CVE-2015-3291",
    "CVE-2015-3331",
    "CVE-2015-3339",
    "CVE-2015-3636",
    "CVE-2015-4167",
    "CVE-2015-4170",
    "CVE-2015-4177",
    "CVE-2015-4692",
    "CVE-2015-4700",
    "CVE-2015-5156"
  );
  script_bugtraq_id(
    72729,
    72730,
    73014,
    73183,
    73699,
    73926,
    74235,
    74243,
    74315,
    74450,
    74951,
    74963,
    75142,
    75356,
    76003,
    76004
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1487)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was found that the Linux kernel's implementation of
    vectored pipe read and write functionality did not take
    into account the I/O vectors that were already
    processed when retrying after a failed atomic access
    operation, potentially resulting in memory corruption
    due to an I/O vector array overrun. A local,
    unprivileged user could use this flaw to crash the
    system or, potentially, escalate their privileges on
    the system.(CVE-2015-1805)

  - net/llc/sysctl_net_llc.c in the Linux kernel before
    3.19 uses an incorrect data type in a sysctl table,
    which allows local users to obtain potentially
    sensitive information from kernel memory or possibly
    have unspecified other impact by accessing a sysctl
    entry.(CVE-2015-2041)

  - net/rds/sysctl.c in the Linux kernel before 3.19 uses
    an incorrect data type in a sysctl table, which allows
    local users to obtain potentially sensitive information
    from kernel memory or possibly have unspecified other
    impact by accessing a sysctl entry.(CVE-2015-2042)

  - Xen 3.3.x through 4.5.x and the Linux kernel through
    3.19.1 do not properly restrict access to PCI command
    registers, which might allow local guest OS users to
    cause a denial of service (non-maskable interrupt and
    host crash) by disabling the (1) memory or (2) I/O
    decoding for a PCI Express device and then accessing
    the device, which triggers an Unsupported Request (UR)
    response.(CVE-2015-2150)

  - A stack-based buffer overflow flaw was found in the
    Linux kernel's early load microcode functionality. On a
    system with UEFI Secure Boot enabled, a local,
    privileged user could use this flaw to increase their
    privileges to the kernel (ring0) level, bypassing
    intended restrictions in place.(CVE-2015-2666)

  - The xsave/xrstor implementation in
    arch/x86/include/asm/xsave.h in the Linux kernel before
    3.19.2 creates certain .altinstr_replacement pointers
    and consequently does not provide any protection
    against instruction faulting, which allows local users
    to cause a denial of service (panic) by triggering a
    fault, as demonstrated by an unaligned memory operand
    or a non-canonical address memory
    operand.(CVE-2015-2672)

  - A flaw was found in the way the Linux kernel's 32-bit
    emulation implementation handled forking or closing of
    a task with an 'int80' entry. A local user could
    potentially use this flaw to escalate their privileges
    on the system.(CVE-2015-2830)

  - It was found that the Linux kernel's TCP/IP protocol
    suite implementation for IPv6 allowed the Hop Limit
    value to be set to a smaller value than the default
    one. An attacker on a local network could use this flaw
    to prevent systems on that network from sending or
    receiving network packets.(CVE-2015-2922)

  - A flaw was found in the way the Linux kernel's file
    system implementation handled rename operations in
    which the source was inside and the destination was
    outside of a bind mount. A privileged user inside a
    container could use this flaw to escape the bind mount
    and, potentially, escalate their privileges on the
    system.(CVE-2015-2925)

  - A race condition flaw was found in the way the Linux
    kernel's SCTP implementation handled Address
    Configuration lists when performing Address
    Configuration Change (ASCONF). A local attacker could
    use this flaw to crash the system via a race condition
    triggered by setting certain ASCONF options on a
    socket.(CVE-2015-3212)

  - mm/memory.c in the Linux kernel before 4.1.4 mishandles
    anonymous pages, which allows local users to gain
    privileges or cause a denial of service (page tainting)
    via a crafted application that triggers writing to page
    zero.(CVE-2015-3288)

  - A flaw was found in the way the Linux kernel's nested
    NMI handler and espfix64 functionalities interacted
    during NMI processing. A local, unprivileged user could
    use this flaw to crash the system or, potentially,
    escalate their privileges on the system.(CVE-2015-3290)

  - It was found that if a Non-Maskable Interrupt (NMI)
    occurred immediately after a SYSCALL call or before a
    SYSRET call with the user RSP pointing to the NMI IST
    stack, the kernel could skip that NMI.(CVE-2015-3291)

  - A buffer overflow flaw was found in the way the Linux
    kernel's Intel AES-NI instructions optimized version of
    the RFC4106 GCM mode decryption functionality handled
    fragmented packets. A remote attacker could use this
    flaw to crash, or potentially escalate their privileges
    on, a system over a connection with an active AES-GCM
    mode IPSec security association.(CVE-2015-3331)

  - A race condition flaw was found between the chown and
    execve system calls. When changing the owner of a
    setuid user binary to root, the race condition could
    momentarily make the binary setuid root. A local,
    unprivileged user could potentially use this flaw to
    escalate their privileges on the system.(CVE-2015-3339)

  - It was found that the Linux kernel's ping socket
    implementation did not properly handle socket unhashing
    during spurious disconnects, which could lead to a
    use-after-free flaw. On x86-64 architecture systems, a
    local user able to create ping sockets could use this
    flaw to crash the system. On non-x86-64 architecture
    systems, a local user able to create ping sockets could
    use this flaw to escalate their privileges on the
    system.(CVE-2015-3636)

  - An inode data validation error was found in Linux
    kernels built with UDF file system (CONFIG_UDF_FS)
    support. An attacker able to mount a
    corrupted/malicious UDF file system image could cause
    the kernel to crash.(CVE-2015-4167)

  - A flaw was discovered in the way the Linux kernel's TTY
    subsystem handled the tty shutdown phase. A local,
    unprivileged user could use this flaw to cause denial
    of service on the system by holding a reference to the
    ldisc lock during tty shutdown, causing a
    deadlock.(CVE-2015-4170)

  - A flaw was discovered in the kernel's collect_mounts
    function. If the kernel's audit subsystem called
    collect_mounts to audit an unmounted path, it could
    panic the system. With this flaw, an unprivileged user
    could call umount(MNT_DETACH) to launch a
    denial-of-service attack.(CVE-2015-4177)

  - A DoS flaw was found for a Linux kernel built for the
    x86 architecture which had the KVM virtualization
    support(CONFIG_KVM) enabled. The kernel would be
    vulnerable to a NULL pointer dereference flaw in Linux
    kernel's kvm_apic_has_events() function while doing an
    ioctl. An unprivileged user able to access the
    '/dev/kvm' device could use this flaw to crash the
    system kernel.(CVE-2015-4692)

  - A flaw was found in the kernel's implementation of the
    Berkeley Packet Filter (BPF). A local attacker could
    craft BPF code to crash the system by creating a
    situation in which the JIT compiler would fail to
    correctly optimize the JIT image on the last pass. This
    would lead to the CPU executing instructions that were
    not part of the JIT code.(CVE-2015-4700)

  - A buffer overflow flaw was found in the way the Linux
    kernel's virtio-net subsystem handled certain fraglists
    when the GRO (Generic Receive Offload) functionality
    was enabled in a bridged network configuration. An
    attacker on the local network could potentially use
    this flaw to crash the system, or, although unlikely,
    elevate their privileges on the system.(CVE-2015-5156)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1487
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54ff0985");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3331");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
