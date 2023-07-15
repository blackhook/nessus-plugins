#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125101);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2013-7281",
    "CVE-2014-0206",
    "CVE-2014-2706",
    "CVE-2014-9090",
    "CVE-2015-8966",
    "CVE-2016-2187",
    "CVE-2016-2384",
    "CVE-2016-2543",
    "CVE-2016-4569",
    "CVE-2016-5342",
    "CVE-2016-8632",
    "CVE-2017-11176",
    "CVE-2017-12154",
    "CVE-2017-16646",
    "CVE-2017-16649",
    "CVE-2018-12714",
    "CVE-2018-13095",
    "CVE-2018-14634",
    "CVE-2018-5703",
    "CVE-2018-7755"
  );
  script_bugtraq_id(
    64747,
    66591,
    68176,
    71250
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1513)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in the USB-MIDI Linux kernel driver: a
    double-free error could be triggered for the 'umidi'
    object. An attacker with physical access to the system
    could use this flaw to escalate their
    privileges.(CVE-2016-2384i1/4%0

  - A vulnerability was found in Linux kernel. There is an
    information leak in file 'sound/core/timer.c' of the
    latest mainline Linux kernel, the stack object
    aEURoetreadaEUR has a total size of 32 bytes. It contains a
    8-bytes padding, which is not initialized but sent to
    user via copy_to_user(), resulting a kernel
    leak.(CVE-2016-4569i1/4%0

  - The dgram_recvmsg function in net/ieee802154/dgram.c in
    the Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel stack
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7281i1/4%0

  - The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel through 4.14.11
    allows attackers to cause a denial of service (slab
    out-of-bounds write) or possibly have unspecified other
    impact via vectors involving TLS.(CVE-2018-5703i1/4%0

  - An issue was discovered in the fd_locked_ioctl function
    in drivers/block/floppy.c in the Linux kernel. The
    floppy driver will copy a kernel pointer to user memory
    in response to the FDGETPRM ioctl. An attacker can send
    the FDGETPRM ioctl and use the obtained kernel pointer
    to discover the location of kernel code and data and
    bypass kernel security protections such as
    KASLR.(CVE-2018-7755i1/4%0

  - The usbnet_generic_cdc_bind function in
    drivers/net/usb/cdc_ether.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16649i1/4%0

  - Heap-based buffer overflow in the wcnss_wlan_write
    function in drivers/net/wireless/wcnss/wcnss_wlan.c in
    the wcnss_wlan device driver for the Linux kernel 3.x,
    as used in Qualcomm Innovation Center (QuIC) Android
    contributions for MSM devices and other products,
    allows attackers to cause a denial of service or
    possibly have unspecified other impact by writing to
    /dev/wcnss_wlan with an unexpected amount of
    data.(CVE-2016-5342i1/4%0

  - drivers/media/usb/dvb-usb/dib0700_devices.c in the
    Linux kernel through 4.13.11 allows local users to
    cause a denial of service (BUG and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16646i1/4%0

  - A flaw was found in the TIPC networking subsystem which
    could allow for memory corruption and possible
    privilege escalation. The flaw involves a system with
    an unusually low MTU (60) on networking devices
    configured as bearers for the TIPC protocol. An
    attacker could create a packet which will overwrite
    memory outside of allocated space and allow for
    privilege escalation.(CVE-2016-8632i1/4%0

  - An issue was discovered in the XFS filesystem in
    fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel. A
    denial of service due to the NULL pointer dereference
    can occur for a corrupted xfs image upon encountering
    an inode that is in extent format, but has more extents
    than fit in the inode fork.(CVE-2018-13095i1/4%0

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization (nVMX) feature
    enabled (nested=1), is vulnerable to a crash due to
    disabled external interrupts. As L2 guest could access
    (r/w) hardware CR8 register of the host(L0). In a
    nested visualization setup, L2 guest user could use
    this flaw to potentially crash the host(L0) resulting
    in DoS.(CVE-2017-12154i1/4%0

  - The do_double_fault function in arch/x86/kernel/traps.c
    in the Linux kernel through 3.17.4 does not properly
    handle faults associated with the Stack Segment (SS)
    segment register, which allows local users to cause a
    denial of service (panic) via a modify_ldt system call,
    as demonstrated by sigreturn_32 in the
    linux-clock-tests test suite.(CVE-2014-9090i1/4%0

  - A race condition flaw was found in the way the Linux
    kernel's mac80211 subsystem implementation handled
    synchronization between TX and STA wake-up code paths.
    A remote attacker could use this flaw to crash the
    system.(CVE-2014-2706i1/4%0

  - The snd_seq_ioctl_remove_events function in
    sound/core/seq/seq_clientmgr.c in the Linux kernel
    before 4.4.1 does not verify FIFO assignment before
    proceeding with FIFO clearing, which allows local users
    to cause a denial of service (NULL pointer dereference
    and OOPS) via a crafted ioctl call.(CVE-2016-2543i1/4%0

  - The gtco_probe function in drivers/input/tablet/gtco.c
    in the Linux kernel through 4.5.2 allows physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    endpoints value in a USB device
    descriptor.(CVE-2016-2187i1/4%0

  - An integer overflow flaw was found in the Linux
    kernel's create_elf_tables() function. An unprivileged
    local user with access to SUID (or otherwise
    privileged) binary could use this flaw to escalate
    their privileges on the system.(CVE-2018-14634i1/4%0

  - A use-after-free flaw was found in the Netlink
    functionality of the Linux kernel networking subsystem.
    Due to the insufficient cleanup in the mq_notify
    function, a local attacker could potentially use this
    flaw to escalate their privileges on the
    system.(CVE-2017-11176i1/4%0

  - Array index error in the aio_read_events_ring function
    in fs/aio.c in the Linux kernel through 3.15.1 allows
    local users to obtain sensitive information from kernel
    memory via a large head value.(CVE-2014-0206i1/4%0

  - arch/arm/kernel/sys_oabi-compat.c in the Linux kernel
    before 4.4 allows local users to gain privileges via a
    crafted (1) F_OFD_GETLK, (2) F_OFD_SETLK, or (3)
    F_OFD_SETLKW command in an fcntl64 system
    call.(CVE-2015-8966i1/4%0

  - An issue was discovered in the Linux kernel through
    4.17.2. The filter parsing in
    kernel/trace/trace_events_filter.c could be called with
    no filter, which is an N=0 case when it expected at
    least one line to have been read, thus making the N-1
    index invalid. This allows attackers to cause a denial
    of service (slab out-of-bounds write) or possibly have
    unspecified other impact via crafted perf_event_open
    and mmap system calls.(CVE-2018-12714i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1513
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2b096c1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

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
