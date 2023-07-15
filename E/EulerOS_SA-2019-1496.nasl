#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124819);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-7117",
    "CVE-2016-7425",
    "CVE-2016-7910",
    "CVE-2016-7911",
    "CVE-2016-7913",
    "CVE-2016-7914",
    "CVE-2016-7915",
    "CVE-2016-7916",
    "CVE-2016-8399",
    "CVE-2016-8630",
    "CVE-2016-8633",
    "CVE-2016-8645",
    "CVE-2016-8646",
    "CVE-2016-8650",
    "CVE-2016-8655",
    "CVE-2016-8666",
    "CVE-2016-9083",
    "CVE-2016-9084",
    "CVE-2016-9555",
    "CVE-2016-9576",
    "CVE-2016-9588",
    "CVE-2016-9604",
    "CVE-2016-9685"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1496)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free vulnerability was found in the
    kernel's socket recvmmsg subsystem. This may allow
    remote attackers to corrupt memory and may allow
    execution of arbitrary code. This corruption takes
    place during the error handling routines within
    __sys_recvmmsg() function.(CVE-2016-7117)

  - A heap-buffer overflow vulnerability was found in the
    arcmsr_iop_message_xfer() function in
    'drivers/scsi/arcmsr/arcmsr_hba.c' file in the Linux
    kernel through 4.8.2. The function does not restrict a
    certain length field, which allows local users to gain
    privileges or cause a denial of service via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code. This can
    potentially cause kernel heap corruption and arbitrary
    kernel code execution.(CVE-2016-7425)

  - A flaw was found in the Linux kernel's implementation
    of seq_file where a local attacker could manipulate
    memory in the put() function pointer. This could lead
    to memory corruption and possible privileged
    escalation.(CVE-2016-7910)

  - A use-after-free vulnerability in sys_ioprio_get() was
    found due to get_task_ioprio() accessing the
    task-i1/4zio_context without holding the task lock and
    could potentially race with exit_io_context(), leading
    to a use-after-free.(CVE-2016-7911)

  - The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    before 4.6 allows local users to gain privileges or
    cause a denial of service (use-after-free) via vectors
    involving omission of the firmware name from a certain
    data structure. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2016-7913)

  - The assoc_array_insert_into_terminal_node() function in
    'lib/assoc_array.c' in the Linux kernel before 4.5.3
    does not check whether a slot is a leaf, which allows
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (invalid pointer
    dereference and out-of-bounds read) via an application
    that uses associative-array data
    structures.(CVE-2016-7914)

  - The hid_input_field() function in
    'drivers/hid/hid-core.c' in the Linux kernel before 4.6
    allows physically proximate attackers to obtain
    sensitive information from kernel memory or cause a
    denial of service (out-of-bounds read) by connecting a
    device.(CVE-2016-7915)

  - Race condition in the environ_read() function in
    'fs/proc/base.c' in the Linux kernel before 4.5.4
    allows local users to obtain sensitive information from
    kernel memory by reading a '/proc/*/environ' file
    during a process-setup time interval in which
    environment-variable copying is
    incomplete.(CVE-2016-7916)

  - A flaw was found in the Linux networking subsystem
    where a local attacker with CAP_NET_ADMIN capabilities
    could cause an out-of-bounds memory access by creating
    a smaller-than-expected ICMP header and sending to its
    destination via sendto().(CVE-2016-8399)

  - Linux kernel built with the Kernel-based Virtual
    Machine (CONFIG_KVM) support is vulnerable to a null
    pointer dereference flaw. It could occur on x86
    platform, when emulating an undefined instruction. An
    attacker could use this flaw to crash the host kernel
    resulting in DoS.(CVE-2016-8630)

  - A buffer overflow vulnerability due to a lack of input
    filtering of incoming fragmented datagrams was found in
    the IP-over-1394 driver firewire-net in a fragment
    handling code in the Linux kernel. The vulnerability
    exists since firewire supported IPv4, i.e. since
    version 2.6.31 (year 2009) till version v4.9-rc4. A
    maliciously formed fragment with a respectively large
    datagram offset would cause a memcpy() past the
    datagram buffer, which would cause a system panic or
    possible arbitrary code execution.The flaw requires
    firewire-net module to be loaded and is remotely
    exploitable from connected firewire devices, but not
    over a local network.(CVE-2016-8633)

  - It was discovered that the Linux kernel since 3.6-rc1
    with 'net.ipv4.tcp_fastopen' set to 1 can hit BUG()
    statement in tcp_collapse() function after making a
    number of certain syscalls leading to a possible system
    crash.(CVE-2016-8645)

  - A vulnerability was found in the Linux kernel. An
    unprivileged local user could trigger oops in
    shash_async_export() by attempting to force the
    in-kernel hashing algorithms into decrypting an empty
    data set.(CVE-2016-8646)

  - A flaw was found in the Linux kernel key management
    subsystem in which a local attacker could crash the
    kernel or corrupt the stack and additional memory
    (denial of service) by supplying a specially crafted
    RSA key. This flaw panics the machine during the
    verification of the RSA key.(CVE-2016-8650)

  - A race condition issue leading to a use-after-free flaw
    was found in the way the raw packet sockets
    implementation in the Linux kernel networking subsystem
    handled synchronization while creating the TPACKET_V3
    ring buffer. A local user able to open a raw packet
    socket (requires the CAP_NET_RAW capability) could use
    this flaw to elevate their privileges on the
    system.(CVE-2016-8655)

  - A flaw was found in the way the Linux kernel's
    networking subsystem handled offloaded packets with
    multiple layers of encapsulation in the GRO (Generic
    Receive Offload) code path. A remote attacker could use
    this flaw to trigger unbounded recursion in the kernel
    that could lead to stack corruption, resulting in a
    system crash.(CVE-2016-8666)

  - A flaw was discovered in the Linux kernel's
    implementation of VFIO. An attacker issuing an ioctl
    can create a situation where memory is corrupted and
    modify memory outside of the expected area. This may
    overwrite kernel memory and subvert kernel
    execution.(CVE-2016-9083)

  - The use of a kzalloc with an integer multiplication
    allowed an integer overflow condition to be reached in
    vfio_pci_intrs.c. This combined with CVE-2016-9083 may
    allow an attacker to craft an attack and use
    unallocated memory, potentially crashing the
    machine.(CVE-2016-9084)

  - A flaw was found in the Linux kernel's implementation
    of the SCTP protocol. A remote attacker could trigger
    an out-of-bounds read with an offset of up to 64kB
    potentially causing the system to crash.(CVE-2016-9555)

  - It was found that the blk_rq_map_user_iov() function in
    the Linux kernel's block device implementation did not
    properly restrict the type of iterator, which could
    allow a local attacker to read or write to arbitrary
    kernel memory locations or cause a denial of service
    (use-after-free) by leveraging write access to a
    /dev/sg device.(CVE-2016-9576)

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization(nVMX) feature
    enabled(nested=1), is vulnerable to an uncaught
    exception issue. It could occur if an L2 guest was to
    throw an exception which is not handled by an L1
    guest.(CVE-2016-9588)

  - It was discovered that root can gain direct access to
    an internal keyring, such as '.dns_resolver' in RHEL-7
    or '.builtin_trusted_keys' upstream, by joining it as
    its session keyring. This allows root to bypass module
    signature verification by adding a new public key of
    its own devising to the keyring.(CVE-2016-9604)

  - A flaw was found in the Linux kernel's implementation
    of XFS file attributes. Two memory leaks were detected
    in xfs_attr_shortform_list and xfs_attr3_leaf_list_int
    when running a docker container backed by xfs/overlay2.
    A dedicated attacker could possible exhaust all memory
    and create a denial of service
    situation.(CVE-2016-9685)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1496
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3326f978");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET chocobo_root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
