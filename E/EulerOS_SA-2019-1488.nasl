#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124812);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2015-5157",
    "CVE-2015-5257",
    "CVE-2015-5283",
    "CVE-2015-5307",
    "CVE-2015-5364",
    "CVE-2015-5366",
    "CVE-2015-5697",
    "CVE-2015-5707",
    "CVE-2015-6252",
    "CVE-2015-6526",
    "CVE-2015-6937",
    "CVE-2015-7312",
    "CVE-2015-7513",
    "CVE-2015-7515",
    "CVE-2015-7550",
    "CVE-2015-7566",
    "CVE-2015-7613",
    "CVE-2015-7799",
    "CVE-2015-7872",
    "CVE-2015-7990",
    "CVE-2015-8104",
    "CVE-2015-8215"
  );
  script_bugtraq_id(
    75510,
    76005
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1488)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in the way the Linux kernel handled
    IRET faults during the processing of NMIs. An
    unprivileged, local user could use this flaw to crash
    the system or, potentially (although highly unlikely),
    escalate their privileges on the system.(CVE-2015-5157)

  - A denial of service vulnerability was found in the
    WhiteHEAT USB Serial Driver (whiteheat_attach function
    in drivers/usb/serial/whiteheat.c). In the driver, the
    COMMAND_PORT variable was hard coded and set to 4 (5th
    element). The driver assumed that the number of ports
    would always be 5 and used port number 5 as the command
    port. However, when using a USB device in which the
    number of ports was set to a number less than 5 (for
    example, 3), the driver triggered a kernel NULL-pointer
    dereference. A non-privileged attacker could use this
    flaw to panic the host.(CVE-2015-5257)

  - A NULL pointer dereference flaw was found in the SCTP
    implementation. A local user could use this flaw to
    cause a denial of service on the system by triggering a
    kernel panic when creating multiple sockets in parallel
    while the system did not have the SCTP module
    loaded.(CVE-2015-5283)

  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as
    #AC (alignment check exception) is handled. A
    privileged user inside a guest could use this flaw to
    create denial of service conditions on the host
    kernel.(CVE-2015-5307)

  - A flaw was found in the way the Linux kernel's
    networking implementation handled UDP packets with
    incorrect checksum values. A remote attacker could
    potentially use this flaw to trigger an infinite loop
    in the kernel, resulting in a denial of service on the
    system, or cause a denial of service in applications
    using the edge triggered epoll
    functionality.(CVE-2015-5364)

  - A flaw was found in the way the Linux kernel's
    networking implementation handled UDP packets with
    incorrect checksum values. A remote attacker could
    potentially use this flaw to trigger an infinite loop
    in the kernel, resulting in a denial of service on the
    system, or cause a denial of service in applications
    using the edge triggered epoll
    functionality.(CVE-2015-5366)

  - A cross-boundary flaw was discovered in the Linux
    kernel software raid driver. The driver accessed a
    disabled bitmap where only the first byte of the buffer
    was initialized to zero. This meant that the rest of
    the request (up to 4095 bytes) was left and copied into
    user space. An attacker could use this flaw to read
    private information from user space that would not
    otherwise have been accessible.(CVE-2015-5697)

  - An integer-overflow vulnerability was found in the scsi
    block-request handling code in function start_req(). A
    local attacker could use specially crafted IOV requests
    to overflow a counter used in bio_map_user_iov()'s page
    calculation, and write past the end of the array that
    contains kernel-page pointers.(CVE-2015-5707)

  - A flaw was found in the way the Linux kernel's vhost
    driver treated userspace provided log file descriptor
    when processing the VHOST_SET_LOG_FD ioctl command. The
    file descriptor was never released and continued to
    consume kernel memory. A privileged local user with
    access to the /dev/vhost-net files could use this flaw
    to create a denial-of-service attack.(CVE-2015-6252)

  - A flaw was found in the way the Linux kernel's perf
    subsystem retrieved userlevel stack traces on PowerPC
    systems. A local, unprivileged user could use this flaw
    to cause a denial of service on the system by creating
    a special stack layout that would force the
    perf_callchain_user_64() function into an infinite
    loop.(CVE-2015-6526)

  - A NULL-pointer dereference vulnerability was discovered
    in the Linux kernel. The kernel's Reliable Datagram
    Sockets (RDS) protocol implementation did not verify
    that an underlying transport existed before creating a
    connection to a remote server. A local system user
    could exploit this flaw to crash the system by creating
    sockets at specific times to trigger a NULL pointer
    dereference.(CVE-2015-6937)

  - Multiple race conditions in the Advanced Union
    Filesystem (aufs) aufs3-mmap.patch and aufs4-mmap.patch
    patches for the Linux kernel 3.x and 4.x allow local
    users to cause a denial of service (use-after-free and
    BUG) or possibly gain privileges via a (1) madvise or
    (2) msync system call, related to mm/madvise.c and
    mm/msync.c.(CVE-2015-7312)

  - A divide-by-zero flaw was discovered in the Linux
    kernel built with KVM virtualization
    support(CONFIG_KVM). The flaw occurs in the KVM
    module's Programmable Interval Timer(PIT) emulation,
    when PIT counters for channel 1 or 2 are set to zero(0)
    and a privileged user inside the guest attempts to read
    these counters. A privileged guest user with access to
    PIT I/O ports could exploit this issue to crash the
    host kernel (denial of service).(CVE-2015-7513)

  - An out-of-bounds memory access flaw was found in the
    Linux kernel's aiptek USB tablet driver (aiptek_probe()
    function in drivers/input/tablet/aiptek.c). The driver
    assumed that the interface always had at least one
    endpoint. By using a specially crafted USB device with
    no endpoints on one of its interfaces, an unprivileged
    user with physical access to the system could trigger a
    kernel NULL pointer dereference, causing the system to
    panic.(CVE-2015-7515)

  - A NULL-pointer dereference flaw was found in the
    kernel, which is caused by a race between revoking a
    user-type key and reading from it. The issue could be
    triggered by an unprivileged user with a local account,
    causing the kernel to crash (denial of
    service).(CVE-2015-7550)

  - A flaw was found in the way the Linux kernel visor
    driver handles certain invalid USB device descriptors.
    The driver assumes that the device always has at least
    one bulk OUT endpoint. By using a specially crafted USB
    device (without a bulk OUT endpoint), an unprivileged
    user with physical access could trigger a kernel
    NULL-pointer dereference and cause a system panic
    (denial of service).(CVE-2015-7566)

  - A race condition flaw was found in the way the Linux
    kernel's IPC subsystem initialized certain fields in an
    IPC object structure that were later used for
    permission checking before inserting the object into a
    globally visible list. A local, unprivileged user could
    potentially use this flaw to elevate their privileges
    on the system.(CVE-2015-7613)

  - A flaw was discovered in the Linux kernel where issuing
    certain ioctl() -s commands to the '/dev/ppp' device
    file could lead to a NULL pointer dereference. A
    privileged user could use this flaw to cause a kernel
    crash and denial of service.(CVE-2015-7799)

  - It was found that the Linux kernel's keys subsystem did
    not correctly garbage collect uninstantiated keyrings.
    A local attacker could use this flaw to crash the
    system or, potentially, escalate their privileges on
    the system.(CVE-2015-7872)

  - A denial of service flaw was discovered in the Linux
    kernel, where a race condition caused a NULL pointer
    dereference in the RDS socket-creation code. A local
    attacker could use this flaw to create a situation in
    which a NULL pointer crashed the kernel.(CVE-2015-7990)

  - It was found that the x86 ISA (Instruction Set
    Architecture) is prone to a denial of service attack
    inside a virtualized environment in the form of an
    infinite loop in the microcode due to the way
    (sequential) delivering of benign exceptions such as
    #DB (debug exception) is handled. A privileged user
    inside a guest could use this flaw to create denial of
    service conditions on the host kernel.(CVE-2015-8104)

  - It was found that the Linux kernel's IPv6 network stack
    did not properly validate the value of the MTU variable
    when it was set. A remote attacker could potentially
    use this flaw to disrupt a target system's networking
    (packet loss) by setting an invalid MTU value, for
    example, via a NetworkManager daemon that is processing
    router advertisement packets running on the target
    system.(CVE-2015-8215)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1488
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0073ce36");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5157");
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
