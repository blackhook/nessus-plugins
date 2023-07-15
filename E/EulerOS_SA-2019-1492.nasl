#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124816);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-2545",
    "CVE-2016-2546",
    "CVE-2016-2547",
    "CVE-2016-2548",
    "CVE-2016-2549",
    "CVE-2016-2550",
    "CVE-2016-2847",
    "CVE-2016-3070",
    "CVE-2016-3134",
    "CVE-2016-3135",
    "CVE-2016-3136",
    "CVE-2016-3137",
    "CVE-2016-3138",
    "CVE-2016-3139",
    "CVE-2016-3140",
    "CVE-2016-3156",
    "CVE-2016-3672",
    "CVE-2016-3689",
    "CVE-2016-3841",
    "CVE-2016-3955",
    "CVE-2016-4470",
    "CVE-2016-4482",
    "CVE-2016-4565"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1492)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The snd_timer_interrupt function in sound/core/timer.c
    in the Linux kernel before 4.4.1 does not properly
    maintain a certain linked list, which allows local
    users to cause a denial of service (race condition and
    system crash) via a crafted ioctl call.(CVE-2016-2545)

  - sound/core/timer.c in the Linux kernel before 4.4.1
    uses an incorrect type of mutex, which allows local
    users to cause a denial of service (race condition,
    use-after-free, and system crash) via a crafted ioctl
    call.(CVE-2016-2546)

  - sound/core/timer.c in the Linux kernel before 4.4.1
    employs a locking approach that does not consider slave
    timer instances, which allows local users to cause a
    denial of service (race condition, use-after-free, and
    system crash) via a crafted ioctl call.(CVE-2016-2547)

  - sound/core/timer.c in the Linux kernel before 4.4.1
    retains certain linked lists after a close or stop
    action, which allows local users to cause a denial of
    service (system crash) via a crafted ioctl call,
    related to the (1) snd_timer_close and (2)
    _snd_timer_stop functions.(CVE-2016-2548)

  - sound/core/hrtimer.c in the Linux kernel before 4.4.1
    does not prevent recursive callback access, which
    allows local users to cause a denial of service
    (deadlock) via a crafted ioctl call.(CVE-2016-2549)

  - A resource-exhaustion vulnerability was found in the
    kernel, where an unprivileged process could allocate
    and accumulate far more file descriptors than the
    process' limit. A local, unauthenticated user could
    exploit this flaw by sending file descriptors over a
    Unix socket and then closing them to keep the process'
    fd count low, thereby creating kernel-memory or
    file-descriptors exhaustion (denial of
    service).(CVE-2016-2550)

  - It is possible for a single process to cause an OOM
    condition by filling large pipes with data that are
    never read. A typical process filling 4096 pipes with 1
    MB of data will use 4 GB of memory and there can be
    multiple such processes, up to a
    per-user-limit.(CVE-2016-2847)

  - A security flaw was found in the Linux kernel that an
    attempt to move page mapped by AIO ring buffer to the
    other node triggers NULL pointer dereference at
    trace_writeback_dirty_page(), because
    aio_fs_backing_dev_info.dev is 0.(CVE-2016-3070)

  - A security flaw was found in the Linux kernel in the
    mark_source_chains() function in
    'net/ipv4/netfilter/ip_tables.c'. It is possible for a
    user-supplied 'ipt_entry' structure to have a large
    'next_offset' field. This field is not bounds checked
    prior to writing to a counter value at the supplied
    offset.(CVE-2016-3134)

  - An integer overflow vulnerability was found in the
    Linux kernel in xt_alloc_table_info, which on 32-bit
    systems can lead to small structure allocation and a
    copy_from_user based heap corruption.(CVE-2016-3135)

  - The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted USB device without two
    interrupt-in endpoint descriptors.(CVE-2016-3136)

  - drivers/usb/serial/cypress_m8.c in the Linux kernel
    before 4.5.1 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions.(CVE-2016-3137)

  - The acm_probe function in drivers/usb/class/cdc-acm.c
    in the Linux kernel before 4.5.1 allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and system crash) via a USB device
    without both a control and a data endpoint
    descriptor.(CVE-2016-3138)

  - The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    before 3.17 allows physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a crafted endpoints value in a USB
    device descriptor.(CVE-2016-3139)

  - The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux
    kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a crafted endpoints
    value in a USB device descriptor.(CVE-2016-3140)

  - 'A security flaw was found in the Linux kernel's
    networking subsystem that destroying the network
    interface with huge number of ipv4 addresses assigned
    keeps ''rtnl_lock'' spinlock for a very long time (up
    to hour). This blocks many network-related operations,
    including creation of new incoming ssh connections.

  - The problem is especially important for containers, as
    the container owner has enough permissions to trigger
    this and block a network access on a whole host,
    outside the container.(CVE-2016-3156)'

  - A weakness was found in the Linux ASLR implementation.
    Any user able to running 32-bit applications in a x86
    machine can disable ASLR by setting the RLIMIT_STACK
    resource to unlimited.(CVE-2016-3672)

  - The ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel before
    4.5.1 allows physically proximate attackers to cause a
    denial of service (system crash) via a USB device
    without both a master and a slave
    interface.(CVE-2016-3689)

  - It was found that the Linux kernel's IPv6
    implementation mishandled socket options. A local
    attacker could abuse concurrent access to the socket
    options to escalate their privileges, or cause a denial
    of service (use-after-free and system crash) via a
    crafted sendmsg system call.(CVE-2016-3841)

  - The usbip_recv_xbuff function in
    drivers/usb/usbip/usbip_common.c in the Linux kernel
    before 4.5.3 allows remote attackers to cause a denial
    of service (out-of-bounds write) or possibly have
    unspecified other impact via a crafted length value in
    a USB/IP packet.(CVE-2016-3955)

  - A flaw was found in the Linux kernel's keyring handling
    code: the key_reject_and_link() function could be
    forced to free an arbitrary memory block. An attacker
    could use this flaw to trigger a use-after-free
    condition on the system, potentially allowing for
    privilege escalation.(CVE-2016-4470)

  - The proc_connectinfo() function in
    'drivers/usb/core/devio.c' in the Linux kernel through
    4.6 does not initialize a certain data structure, which
    allows local users to obtain sensitive information from
    kernel stack memory via a crafted USBDEVFS_CONNECTINFO
    ioctl call. The stack object 'ci' has a total size of 8
    bytes. Its last 3 bytes are padding bytes which are not
    initialized and are leaked to userland.(CVE-2016-4482)

  - A flaw was found in the way certain interfaces of the
    Linux kernel's Infiniband subsystem used write() as
    bi-directional ioctl() replacement, which could lead to
    insufficient memory security checks when being invoked
    using the splice() system call. A local unprivileged
    user on a system with either Infiniband hardware
    present or RDMA Userspace Connection Manager Access
    module explicitly loaded, could use this flaw to
    escalate their privileges on the system.(CVE-2016-4565)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1492
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3a99eaa");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
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
