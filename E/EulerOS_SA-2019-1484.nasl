#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124808);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-7266",
    "CVE-2014-2672",
    "CVE-2014-2678",
    "CVE-2014-8086",
    "CVE-2015-0569",
    "CVE-2015-2150",
    "CVE-2015-3331",
    "CVE-2015-5307",
    "CVE-2015-5366",
    "CVE-2016-4440",
    "CVE-2016-7117",
    "CVE-2016-7914",
    "CVE-2017-1000410",
    "CVE-2017-17052",
    "CVE-2017-18222",
    "CVE-2017-6214",
    "CVE-2018-10087",
    "CVE-2018-10878",
    "CVE-2018-13100",
    "CVE-2018-18690"
  );
  script_bugtraq_id(
    64743,
    66492,
    66543,
    70376,
    73014,
    74235,
    75510
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1484)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In the Linux kernel, Hisilicon Network Subsystem (HNS)
    does not consider the ETH_SS_PRIV_FLAGS case when
    retrieving sset_count data. This allows local users to
    cause a denial of service (buffer overflow and memory
    corruption) or possibly have unspecified other
    impacts.(CVE-2017-18222i1/4%0

  - A flaw was found in the way the Linux kernel's
    networking implementation handled UDP packets with
    incorrect checksum values. A remote attacker could
    potentially use this flaw to trigger an infinite loop
    in the kernel, resulting in a denial of service on the
    system, or cause a denial of service in applications
    using the edge triggered epoll
    functionality.(CVE-2015-5366i1/4%0

  - A use-after-free vulnerability was found in the
    kernel's socket recvmmsg subsystem. This may allow
    remote attackers to corrupt memory and may allow
    execution of arbitrary code. This corruption takes
    place during the error handling routines within
    __sys_recvmmsg() function.(CVE-2016-7117i1/4%0

  - arch/x86/kvm/vmx.c in the Linux kernel through 4.6.3
    mishandles the APICv on/off state, which allows guest
    OS users to obtain direct APIC MSR access on the host
    OS, and consequently cause a denial of service (host OS
    crash) or possibly execute arbitrary code on the host
    OS, via x2APIC mode.(CVE-2016-4440i1/4%0

  - In the Linux kernel before 4.17, a local attacker able
    to set attributes on an xfs filesystem could make this
    filesystem non-operational until the next mount by
    triggering an unchecked error condition during an xfs
    attribute change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandles ATTR_REPLACE
    operations with conversion of an attr from short to
    long form.(CVE-2018-18690i1/4%0

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bounds write and a
    denial of service or unspecified other impact is
    possible by mounting and operating a crafted ext4
    filesystem image.(CVE-2018-10878i1/4%0

  - Xen 3.3.x through 4.5.x and the Linux kernel through
    3.19.1 do not properly restrict access to PCI command
    registers, which might allow local guest OS users to
    cause a denial of service (non-maskable interrupt and
    host crash) by disabling the (1) memory or (2) I/O
    decoding for a PCI Express device and then accessing
    the device, which triggers an Unsupported Request (UR)
    response.(CVE-2015-2150i1/4%0

  - The assoc_array_insert_into_terminal_node() function in
    'lib/assoc_array.c' in the Linux kernel before 4.5.3
    does not check whether a slot is a leaf, which allows
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (invalid pointer
    dereference and out-of-bounds read) via an application
    that uses associative-array data
    structures.(CVE-2016-7914i1/4%0

  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as
    #AC (alignment check exception) is handled. A
    privileged user inside a guest could use this flaw to
    create denial of service conditions on the host
    kernel.(CVE-2015-5307i1/4%0

  - An issue was discovered in fs/f2fs/super.c in the Linux
    kernel, which does not properly validate secs_per_zone
    in a corrupted f2fs image. This may lead to a
    divide-by-zero error and a system
    crash.(CVE-2018-13100i1/4%0

  - The mISDN_sock_recvmsg function in
    drivers/isdn/mISDN/socket.c in the Linux kernel before
    3.12.4 does not ensure that a certain length value is
    consistent with the size of an associated data
    structure, which allows local users to obtain sensitive
    information from kernel memory via a (1) recvfrom, (2)
    recvmmsg, or (3) recvmsg system call.(CVE-2013-7266i1/4%0

  - A NULL pointer dereference flaw was found in the
    rds_iw_laddr_check() function in the Linux kernel's
    implementation of Reliable Datagram Sockets (RDS). A
    local, unprivileged user could use this flaw to crash
    the system.(CVE-2014-2678i1/4%0

  - A flaw was found in the Linux kernel's handling of
    packets with the URG flag. Applications using the
    splice() and tcp_splice_read() functionality could
    allow a remote attacker to force the kernel to enter a
    condition in which it could loop
    indefinitely.(CVE-2017-6214i1/4%0

  - The kernel_wait4 function in kernel/exit.c in the Linux
    kernel before 4.13, when an unspecified architecture
    and compiler is used, might allow local users to cause
    a denial of service by triggering an attempted use of
    the -INT_MIN value.(CVE-2018-10087i1/4%0

  - Heap-based buffer overflow in the private wireless
    extensions IOCTL implementation in wlan_hdd_wext.c in
    the WLAN (aka Wi-Fi) driver for the Linux kernel 3.x
    and 4.x, as used in Qualcomm Innovation Center (QuIC)
    Android contributions for MSM devices and other
    products, allows attackers to gain privileges via a
    crafted application that establishes a packet
    filter.(CVE-2015-0569i1/4%0

  - A race condition flaw was found in the Linux kernel's
    ext4 file system implementation that allowed a local,
    unprivileged user to crash the system by simultaneously
    writing to a file and toggling the O_DIRECT flag using
    fcntl(F_SETFL) on that file.(CVE-2014-8086i1/4%0

  - The mm_init function in kernel/fork.c in the Linux
    kernel before 4.12.10 does not clear the -i1/4zexe_file
    member of a new process's mm_struct, allowing a local
    attacker to achieve a use-after-free condition and to
    induce a kernel memory corruption on the system,
    leading to a crash or possibly have unspecified other
    impact by running a specially crafted program. Due to
    the nature of the flaw, privilege escalation cannot be
    fully ruled out, although we feel it is
    unlikely.(CVE-2017-17052i1/4%0

  - A buffer overflow flaw was found in the way the Linux
    kernel's Intel AES-NI instructions optimized version of
    the RFC4106 GCM mode decryption functionality handled
    fragmented packets. A remote attacker could use this
    flaw to crash, or potentially escalate their privileges
    on, a system over a connection with an active AES-GCM
    mode IPSec security association.(CVE-2015-3331i1/4%0

  - A flaw was found in the processing of incoming L2CAP
    bluetooth commands. Uninitialized stack variables can
    be sent to an attacker leaking data in kernel address
    space.(CVE-2017-1000410i1/4%0

  - It was found that a remote attacker could use a race
    condition flaw in the ath_tx_aggr_sleep() function to
    crash the system by creating large network traffic on
    the system's Atheros 9k wireless network
    adapter.(CVE-2014-2672i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1484
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afeb6657");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
