#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124802);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4270",
    "CVE-2013-4299",
    "CVE-2014-5207",
    "CVE-2015-0570",
    "CVE-2015-5697",
    "CVE-2015-8845",
    "CVE-2016-2544",
    "CVE-2016-4558",
    "CVE-2016-5828",
    "CVE-2016-6130",
    "CVE-2017-10911",
    "CVE-2017-16537",
    "CVE-2017-16643",
    "CVE-2017-16647",
    "CVE-2017-2647",
    "CVE-2017-5967",
    "CVE-2017-7472",
    "CVE-2017-7645",
    "CVE-2018-12233",
    "CVE-2018-15572"
  );
  script_bugtraq_id(
    63183,
    64471,
    69216
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1478)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In the ea_get function in fs/jfs/xattr.c in the Linux
    kernel through 4.17.1, a memory corruption bug in JFS
    can be triggered by calling setxattr twice with two
    different extended attribute names on the same file.
    This vulnerability can be triggered by an unprivileged
    user with the ability to create files and execute
    programs. A kmalloc call is incorrect, leading to
    slab-out-of-bounds in jfs_xattr.(CVE-2018-12233i1/4%0

  - The spectre_v2_select_mitigation function in
    arch/x86/kernel/cpu/bugs.c in the Linux kernel before
    4.18.1 does not always fill RSB upon a context switch,
    which makes it easier for attackers to conduct
    userspace-userspace spectreRSB
    attacks.(CVE-2018-15572i1/4%0

  - Race condition in the queue_delete function in
    sound/core/seq/seq_queue.c in the Linux kernel before
    4.4.1 allows local users to cause a denial of service
    (use-after-free and system crash) by making an ioctl
    call at a certain time.(CVE-2016-2544i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of BPF in which systems can application can overflow a
    32 bit refcount in both program and map refcount. This
    refcount can wrap and end up a user after
    free.(CVE-2016-4558i1/4%0

  - Interpretation conflict in
    drivers/md/dm-snap-persistent.c in the Linux kernel
    through 3.11.6 allows remote authenticated users to
    obtain sensitive information or modify data via a
    crafted mapping to a snapshot block
    device.(CVE-2013-4299i1/4%0

  - The imon_probe function in drivers/media/rc/imon.c in
    the Linux kernel through 4.13.11 allows local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16537i1/4%0

  - A vulnerability in the handling of Transactional Memory
    on powerpc systems was found. An unprivileged local
    user can crash the kernel by starting a transaction,
    suspending it, and then calling any of the exec() class
    system calls.(CVE-2016-5828i1/4%0

  - A cross-boundary flaw was discovered in the Linux
    kernel software raid driver. The driver accessed a
    disabled bitmap where only the first byte of the buffer
    was initialized to zero. This meant that the rest of
    the request (up to 4095 bytes) was left and copied into
    user space. An attacker could use this flaw to read
    private information from user space that would not
    otherwise have been accessible.(CVE-2015-5697i1/4%0

  - The parse_hid_report_descriptor function in
    drivers/input/tablet/gtco.c in the Linux kernel before
    4.13.11 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16643i1/4%0

  - Race condition in the sclp_ctl_ioctl_sccb function in
    drivers/s390/char/sclp_ctl.c in the Linux kernel before
    4.6 allows local users to obtain sensitive information
    from kernel memory by changing a certain length value,
    aka a 'double fetch' vulnerability.(CVE-2016-6130i1/4%0

  - drivers/net/usb/asix_devices.c in the Linux kernel
    through 4.13.11 allows local users to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16647i1/4%0

  - A flaw was found in the Linux kernel which could cause
    a kernel panic when restoring machine specific
    registers on the PowerPC platform. Incorrect
    transactional memory state registers could
    inadvertently change the call path on return from
    userspace and cause the kernel to enter an unknown
    state and crash.(CVE-2015-8845i1/4%0

  - fs/namespace.c in the Linux kernel through 3.16.1 does
    not properly restrict clearing MNT_NODEV, MNT_NOSUID,
    and MNT_NOEXEC and changing MNT_ATIME_MASK during a
    remount of a bind mount, which allows local users to
    gain privileges, interfere with backups and auditing on
    systems that had atime enabled, or cause a denial of
    service (excessive filesystem updating) on systems that
    had atime disabled via a 'mount -o remount' command
    within a user namespace.(CVE-2014-5207i1/4%0

  - The NFS2/3 RPC client could send long arguments to the
    NFS server. These encoded arguments are stored in an
    array of memory pages, and accessed using pointer
    variables. Arbitrarily long arguments could make these
    pointers point outside the array and cause an
    out-of-bounds memory access. A remote user or program
    could use this flaw to crash the kernel, resulting in
    denial of service.(CVE-2017-7645i1/4%0

  - The time subsystem in the Linux kernel, when
    CONFIG_TIMER_STATS is enabled, allows local users to
    discover real PID values (as distinguished from PID
    values inside a PID namespace) by reading the
    /proc/timer_list file, related to the print_timer
    function in kernel/time/timer_list.c and the
    __timer_stats_timer_set_start_info function in
    kernel/time/timer.c.(CVE-2017-5967i1/4%0

  - A vulnerability was found in the Linux kernel where the
    keyctl_set_reqkey_keyring() function leaks the thread
    keyring. This allows an unprivileged local user to
    exhaust kernel memory and thus cause a
    DoS.(CVE-2017-7472i1/4%0

  - A flaw was found that can be triggered in
    keyring_search_iterator in keyring.c if type-i1/4zmatch
    is NULL. A local user could use this flaw to crash the
    system or, potentially, escalate their
    privileges.(CVE-2017-2647i1/4%0

  - The make_response function in
    drivers/block/xen-blkback/blkback.c in the Linux kernel
    before 4.11.8 allows guest OS users to obtain sensitive
    information from host OS (or other guest OS) kernel
    memory by leveraging the copying of uninitialized
    padding fields in Xen block-interface response
    structures, aka XSA-216.(CVE-2017-10911i1/4%0

  - Stack-based buffer overflow in the SET_WPS_IE IOCTL
    implementation in wlan_hdd_hostapd.c in the WLAN (aka
    Wi-Fi) driver for the Linux kernel 3.x and 4.x, as used
    in Qualcomm Innovation Center (QuIC) Android
    contributions for MSM devices and other products,
    allows attackers to gain privileges via a crafted
    application that uses a long WPS IE
    element.(CVE-2015-0570i1/4%0

  - The net_ctl_permissions function in net/sysctl_net.c in
    the Linux kernel before 3.11.5 does not properly
    determine uid and gid values, which allows local users
    to bypass intended /proc/sys/net restrictions via a
    crafted application.(CVE-2013-4270i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1478
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f1ad85b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
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
