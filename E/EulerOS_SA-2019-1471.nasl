#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124795);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-2889",
    "CVE-2013-4345",
    "CVE-2013-7421",
    "CVE-2014-0155",
    "CVE-2014-3122",
    "CVE-2014-4014",
    "CVE-2015-3332",
    "CVE-2015-4176",
    "CVE-2016-2184",
    "CVE-2016-2545",
    "CVE-2016-2546",
    "CVE-2017-14340",
    "CVE-2017-16531",
    "CVE-2017-18218",
    "CVE-2017-18360",
    "CVE-2017-5669",
    "CVE-2018-10675",
    "CVE-2018-11232",
    "CVE-2018-18710",
    "CVE-2018-7480"
  );
  script_bugtraq_id(
    62042,
    62740,
    66688,
    67162,
    67988,
    72322,
    74232
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1471)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - drivers/hid/hid-zpff.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_ZEROPLUS is enabled, allows physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2889i1/4%0

  - The capabilities implementation in the Linux kernel
    before 3.14.8 does not properly consider that
    namespaces are inapplicable to inodes, which allows
    local users to bypass intended chmod restrictions by
    first creating a user namespace, as demonstrated by
    setting the setgid bit on a file with group ownership
    of root.(CVE-2014-4014i1/4%0

  - The function drivers/usb/core/config.c in the Linux
    kernel, allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB device,
    related to the USB_DT_INTERFACE_ASSOCIATION
    descriptor.(CVE-2017-16531i1/4%0

  - The snd_timer_interrupt function in sound/core/timer.c
    in the Linux kernel before 4.4.1 does not properly
    maintain a certain linked list, which allows local
    users to cause a denial of service (race condition and
    system crash) via a crafted ioctl
    call.(CVE-2016-2545i1/4%0

  - A flaw was found in the Linux kernel where the deletion
    of a file or directory could trigger an unmount and
    reveal data under a mount point. This flaw was
    inadvertently introduced with the new feature of being
    able to lazily unmount a mount tree when using file
    system user namespaces.(CVE-2015-4176i1/4%0

  - The do_shmat function in ipc/shm.c in the Linux kernel,
    through 4.9.12, does not restrict the address
    calculated by a certain rounding operation. This allows
    privileged local users to map page zero and,
    consequently, bypass a protection mechanism that exists
    for the mmap system call. This is possible by making
    crafted shmget and shmat system calls in a privileged
    context.(CVE-2017-5669i1/4%0

  - In drivers/net/ethernet/hisilicon/hns/hns_enet.c in the
    Linux kernel, before 4.13, local users can cause a
    denial of service (use-after-free and BUG) or possibly
    have unspecified other impact by leveraging differences
    in skb handling between hns_nic_net_xmit_hw and
    hns_nic_net_xmit.(CVE-2017-18218i1/4%0

  - The ioapic_deliver function in virt/kvm/ioapic.c in the
    Linux kernel through 3.14.1 does not properly validate
    the kvm_irq_delivery_to_apic return value, which allows
    guest OS users to cause a denial of service (host OS
    crash) via a crafted entry in the redirection table of
    an I/O APIC. NOTE: the affected code was moved to the
    ioapic_service function before the vulnerability was
    announced.(CVE-2014-0155i1/4%0

  - A flaw was found in the way the Linux kernel's Crypto
    subsystem handled automatic loading of kernel modules.
    A local user could use this flaw to load any installed
    kernel module, and thus increase the attack surface of
    the running kernel.(CVE-2013-7421i1/4%0

  - Off-by-one error in the get_prng_bytes function in
    crypto/ansi_cprng.c in the Linux kernel through 3.11.4
    makes it easier for context-dependent attackers to
    defeat cryptographic protection mechanisms via multiple
    requests for small amounts of data, leading to improper
    management of the state of the consumed
    data.(CVE-2013-4345i1/4%0

  - sound/core/timer.c in the Linux kernel before 4.4.1
    uses an incorrect type of mutex, which allows local
    users to cause a denial of service (race condition,
    use-after-free, and system crash) via a crafted ioctl
    call.(CVE-2016-2546i1/4%0

  - The do_get_mempolicy function in mm/mempolicy.c in the
    Linux kernel before 4.12.9 allows local users to cause
    a denial of service (use-after-free) or possibly have
    unspecified other impact via crafted system
    calls.(CVE-2018-10675i1/4%0

  - A certain backport in the TCP Fast Open implementation
    for the Linux kernel before 3.18 does not properly
    maintain a count value, which allow local users to
    cause a denial of service (system crash) via the Fast
    Open feature, as demonstrated by visiting the
    chrome://flags/#enable-tcp-fast-open URL when using
    certain 3.10.x through 3.16.x kernel builds, including
    longterm-maintenance releases and ckt (aka Canonical
    Kernel Team) builds.(CVE-2015-3332i1/4%0

  - It was found that the try_to_unmap_cluster() function
    in the Linux kernel's Memory Managment subsystem did
    not properly handle page locking in certain cases,
    which could potentially trigger the BUG_ON() macro in
    the mlock_vma_page() function. A local, unprivileged
    user could use this flaw to crash the
    system.(CVE-2014-3122i1/4%0

  - The blkcg_init_queue function in block/blk-cgroup.c in
    the Linux kernel, before 4.11, allows local users to
    cause a denial of service (double free) or possibly
    have unspecified other impact by triggering a creation
    failure.(CVE-2018-7480i1/4%0

  - The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (NULL pointer
    dereference or double free, and system crash) via a
    crafted endpoints value in a USB device
    descriptor.(CVE-2016-2184i1/4%0

  - The etm_setup_aux function in
    drivers/hwtracing/coresight/coresight-etm-perf.c in the
    Linux kernel before 4.10.2 allows attackers to cause a
    denial of service (panic) because a parameter is
    incorrectly used as a local variable.(CVE-2018-11232i1/4%0

  - A division-by-zero in set_termios(), when debugging is
    enabled, was found in the Linux kernel. When the
    [io_ti] driver is loaded, a local unprivileged attacker
    can request incorrect high transfer speed in the
    change_port_settings() in the
    drivers/usb/serial/io_ti.c so that the divisor value
    becomes zero and causes a system crash resulting in a
    denial of service.(CVE-2017-18360i1/4%0

  - A flaw was found where the XFS filesystem code
    mishandles a user-settable inode flag in the Linux
    kernel prior to 4.14-rc1. This can cause a local denial
    of service via a kernel panic.(CVE-2017-14340i1/4%0

  - An issue was discovered in the Linux kernel through
    4.19. An information leak in cdrom_ioctl_select_disc in
    drivers/cdrom/cdrom.c could be used by local attackers
    to read kernel memory because a cast from unsigned long
    to int interferes with bounds
    checking.(CVE-2018-18710i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1471
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d86ae156");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
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
