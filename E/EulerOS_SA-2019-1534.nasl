#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124987);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2013-7267",
    "CVE-2014-0077",
    "CVE-2014-2851",
    "CVE-2014-3688",
    "CVE-2015-1333",
    "CVE-2015-1421",
    "CVE-2016-0758",
    "CVE-2016-10088",
    "CVE-2016-10723",
    "CVE-2016-4581",
    "CVE-2016-5870",
    "CVE-2016-6786",
    "CVE-2017-1000252",
    "CVE-2017-14954",
    "CVE-2017-16534",
    "CVE-2017-17807",
    "CVE-2017-18241",
    "CVE-2017-9211",
    "CVE-2018-11508",
    "CVE-2018-14619"
  );
  script_bugtraq_id(
    64739,
    66678,
    66779,
    70768,
    72356
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1534)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The atalk_recvmsg function in net/appletalk/ddp.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7267i1/4%0

  - fs/f2fs/segment.c in the Linux kernel allows local
    users to cause a denial of service (NULL pointer
    dereference and panic) by using a noflush_merge option
    that triggers a NULL value for a flush_cmd_control data
    structure.(CVE-2017-18241i1/4%0

  - fs/pnode.c in the Linux kernel before 4.5.4 does not
    properly traverse a mount propagation tree in a certain
    case involving a slave mount, which allows local users
    to cause a denial of service (NULL pointer dereference
    and OOPS) via a crafted series of mount system
    calls.(CVE-2016-4581i1/4%0

  - drivers/vhost/net.c in the Linux kernel before 3.13.10,
    when mergeable buffers are disabled, does not properly
    validate packet lengths, which allows guest OS users to
    cause a denial of service (memory corruption and host
    OS crash) or possibly gain privileges on the host OS
    via crafted packets, related to the handle_rx and
    get_rx_bufs functions.(CVE-2014-0077i1/4%0

  - It was found that the fix for CVE-2016-9576 was
    incomplete: the Linux kernel's sg implementation did
    not properly restrict write operations in situations
    where the KERNEL_DS option is set. A local attacker to
    read or write to arbitrary kernel memory locations or
    cause a denial of service (use-after-free) by
    leveraging write access to a /dev/sg
    device.(CVE-2016-10088i1/4%0

  - ** DISPUTED ** An issue was discovered in the Linux
    kernel through 4.17.2. Since the page allocator does
    not yield CPU resources to the owner of the oom_lock
    mutex, a local unprivileged user can trivially lock up
    the system forever by wasting CPU resources from the
    page allocator (e.g., via concurrent page fault events)
    when the global OOM killer is invoked. NOTE: the
    software maintainer has not accepted certain proposed
    patches, in part because of a viewpoint that 'the
    underlying problem is non-trivial to
    handle.'(CVE-2016-10723i1/4%0

  - A flaw was found in the way the Linux kernel's ASN.1
    DER decoder processed certain certificate files with
    tags of indefinite length. A local, unprivileged user
    could use a specially crafted X.509 certificate DER
    file to crash the system or, potentially, escalate
    their privileges on the system.(CVE-2016-0758i1/4%0

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled the association's output queue. A remote
    attacker could send specially crafted packets that
    would cause the system to use an excessive amount of
    memory, leading to a denial of
    service.(CVE-2014-3688i1/4%0

  - A use-after-free flaw was found in the way the
    ping_init_sock() function of the Linux kernel handled
    the group_info reference counter. A local, unprivileged
    user could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-2851i1/4%0

  - The compat_get_timex function in kernel/compat.c in the
    Linux kernel before 4.16.9 allows local users to obtain
    sensitive information from kernel memory via
    adjtimex.(CVE-2018-11508i1/4%0

  - The cdc_parse_cdc_header() function in
    'drivers/usb/core/message.c' in the Linux kernel,
    before 4.13.6, allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2017-16534i1/4%0

  - A flaw was found in the crypto subsystem of the Linux
    kernel before version kernel-4.15-rc4. The 'null
    skcipher' was being dropped when each af_alg_ctx was
    freed instead of when the aead_tfm was freed. This can
    cause the null skcipher to be freed while it is still
    in use leading to a local user being able to crash the
    system or possibly escalate
    privileges.(CVE-2018-14619i1/4%0

  - The crypto_skcipher_init_tfm function in
    crypto/skcipher.c in the Linux kernel through 4.11.2
    relies on a setkey function that lacks a key-size
    check, which allows local users to cause a denial of
    service (NULL pointer dereference) via a crafted
    application.(CVE-2017-9211i1/4%0

  - kernel/events/core.c in the performance subsystem in
    the Linux kernel before 4.0 mismanages locks during
    certain migrations, which allows local users to gain
    privileges via a crafted application, aka Android
    internal bug 30955111.(CVE-2016-6786i1/4%0

  - The KEYS subsystem in the Linux kernel omitted an
    access-control check when writing a key to the current
    task's default keyring, allowing a local user to bypass
    security checks to the keyring. This compromises the
    validity of the keyring for those who rely on
    it.(CVE-2017-17807i1/4%0

  - A use-after-free flaw was found in the way the Linux
    kernel's SCTP implementation handled authentication key
    reference counting during INIT collisions. A remote
    attacker could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2015-1421i1/4%0

  - The waitid implementation in kernel/exit.c in the Linux
    kernel through 4.13.4 accesses rusage data structures
    in unintended cases. This can allow local users to
    obtain sensitive information and bypass the KASLR
    protection mechanism via a crafted system
    call.(CVE-2017-14954i1/4%0

  - It was found that the Linux kernel's keyring
    implementation would leak memory when adding a key to a
    keyring via the add_key() function. A local attacker
    could use this flaw to exhaust all available memory on
    the system.(CVE-2015-1333i1/4%0

  - The msm_ipc_router_close function in
    net/ipc_router/ipc_router_socket.c in the ipc_router
    component for the Linux kernel 3.x, as used in Qualcomm
    Innovation Center (QuIC) Android contributions for MSM
    devices and other products, allow attackers to cause a
    denial of service (NULL pointer dereference) or
    possibly have unspecified other impact by triggering
    failure of an accept system call for an AF_MSM_IPC
    socket.(CVE-2016-5870i1/4%0

  - A reachable assertion failure flaw was found in the
    Linux kernel built with KVM virtualisation(CONFIG_KVM)
    support with Virtual Function I/O feature (CONFIG_VFIO)
    enabled. This failure could occur if a malicious guest
    device sent a virtual interrupt (guest IRQ) with a
    larger (i1/4z1024) index value.(CVE-2017-1000252i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1534
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c73d2ac");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
