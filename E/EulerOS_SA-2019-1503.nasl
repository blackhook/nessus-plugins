#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124826);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2013-2890",
    "CVE-2013-4512",
    "CVE-2014-0181",
    "CVE-2014-1444",
    "CVE-2014-9717",
    "CVE-2014-9870",
    "CVE-2015-7513",
    "CVE-2015-8967",
    "CVE-2016-10229",
    "CVE-2016-3689",
    "CVE-2016-8658",
    "CVE-2016-9313",
    "CVE-2017-15537",
    "CVE-2017-16530",
    "CVE-2017-5549",
    "CVE-2018-13094",
    "CVE-2018-19407",
    "CVE-2018-20669",
    "CVE-2018-6555",
    "CVE-2018-7273"
  );
  script_bugtraq_id(
    62055,
    63510,
    64952,
    67034,
    74226
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1503)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):The uas driver in the
    Linux kernel before 4.13.6 allows local users to cause
    a denial of service (out-of-bounds read and system
    crash), or possibly have unspecified other impacts via
    a crafted USB device, related to
    drivers/usb/storage/uas-detect.h and
    drivers/usb/storage/uas.c.(CVE-2017-16530)The
    implementation of big key management in
    security/keys/big_key.c in the Linux kernel before
    4.8.7 mishandles unsuccessful crypto registration in
    conjunction with successful key-type registration,
    which allows local users to cause a denial of service
    (NULL pointer dereference and panic) or possibly have
    unspecified other impact via a crafted application that
    uses the big_key data type.(CVE-2016-9313)The Linux
    kernel allows remote attackers to execute arbitrary
    code via UDP traffic that triggers an unsafe second
    checksum calculation during execution of a recv system
    call with the MSG_PEEK flag. This may create a kernel
    panic or memory corruption leading to privilege
    escalation.(CVE-2016-10229)Buffer overflow in the
    exitcode_proc_write function in
    arch/um/kernel/exitcode.c in the Linux kernel before
    3.12 allows local users to cause a denial of service or
    possibly have unspecified other impact by leveraging
    root privileges for a write operation.(CVE-2013-4512)It
    was found that unsharing a mount namespace could allow
    a user to see data beneath their restricted
    namespace.(CVE-2014-9717)A divide-by-zero flaw was
    discovered in the Linux kernel built with KVM
    virtualization support(CONFIG_KVM). The flaw occurs in
    the KVM module's Programmable Interval Timer(PIT)
    emulation, when PIT counters for channel 1 or 2 are set
    to zero(0) and a privileged user inside the guest
    attempts to read these counters. A privileged guest
    user with access to PIT I/O ports could exploit this
    issue to crash the host kernel (denial of
    service).(CVE-2015-7513)The ims_pcu_parse_cdc_data
    function in drivers/input/misc/ims-pcu.c in the Linux
    kernel before 4.5.1 allows physically proximate
    attackers to cause a denial of service (system crash)
    via a USB device without both a master and a slave
    interface.(CVE-2016-3689)Stack-based buffer overflow in
    the brcmf_cfg80211_start_ap() function in
    'driverset/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c' in the Linux kernel before 4.7.5 allows local
    users to cause a denial of service (system crash) or
    possibly have unspecified other impact via a long SSID
    Information Element in a command to a Netlink
    socket.(CVE-2016-8658)drivers/hid/hid-sony.c in the
    Human Interface Device (HID) subsystem in the Linux
    kernel through 3.11, when CONFIG_HID_SONY is enabled,
    allows physically proximate attackers to cause a denial
    of service (heap-based out-of-bounds write) via a
    crafted device.(CVE-2013-2890)An issue where a provided
    address with access_ok() is not checked was discovered
    in i915_gem_execbuffer2_ioctl in
    drivers/gpu/drm/i915/i915_gem_execbuffer.c in the Linux
    kernel through 4.19.13. A local attacker can craft a
    malicious IOCTL function call to overwrite arbitrary
    kernel memory, resulting in a Denial of Service or
    privilege escalation.(CVE-2018-20669)It was found that
    the permission checks performed by the Linux kernel
    when a netlink message was received were not
    sufficient. A local, unprivileged user could
    potentially bypass these restrictions by passing a
    netlink socket as stdout or stderr to a more privileged
    process and altering the output of this
    process.(CVE-2014-0181)An issue was discovered in the
    XFS filesystem in fs/xfs/libxfs/xfs_attr_leaf.c in the
    Linux kernel. A NULL pointer dereference may occur for
    a corrupted xfs image after xfs_da_shrink_inode() is
    called with a NULL bp. This can lead to a system crash
    and a denial of service.(CVE-2018-13094)The
    irda_setsockopt function in net/irda/af_irda.c in the
    Linux kernel, through 4.16, allows local users to cause
    a denial of service (due to a use-after-free of the
    ias_object and a system crash) or possibly have
    unspecified other impact by leveraging an AF_IRDA
    socket.(CVE-2018-6555)The x86/fpu (Floating Point Unit)
    subsystem in the Linux kernel, when a processor
    supports the xsave feature but not the xsaves feature,
    does not correctly handle attempts to set reserved bits
    in the xstate header via the ptrace() or rt_sigreturn()
    system call. This allows local users to read the FPU
    registers of other processes on the system, related to
    arch/x86/kernel/fpu/regset.c and
    arch/x86/kernel/fpu/signal.c.(CVE-2017-15537)The
    fst_get_iface function in driverset/wan/farsync.c in
    the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel
    memory by leveraging the CAP_NET_ADMIN capability for
    an SIOCWANDEV ioctl call.(CVE-2014-1444)In the Linux
    kernel, through 4.15.4, the floppy driver reveals the
    addresses of kernel functions and global variables
    using printk calls within the function show_floppy in
    drivers/block/floppy.c. An attacker can read this
    information from dmesg and use the addresses to find
    the locations of kernel code and data and bypass kernel
    security protections such as KASLR.(CVE-2018-7273)A
    flaw in 'arch/arm64/kernel/sys.c' in the Linux kernel
    allows local users to bypass the 'strict page
    permissions' protection mechanism and modify the
    system-call table and, consequently, gain privileges by
    leveraging write access.(CVE-2015-8967)The Linux kernel
    before 3.11 on ARM platforms, as used in Android before
    2016-08-05 on Nexus 5 and 7 (2013) devices, does not
    properly consider user-space access to the TPIDRURW
    register, which allows local users to gain privileges
    via a crafted application, aka Android internal bug
    28749743 and Qualcomm internal bug
    CR561044.(CVE-2014-9870)A NULL pointer dereference
    security flaw was found in the Linux kernel in the
    vcpu_scan_ioapic() function in arch/x86/kvm/x86.c. This
    allows local users with certain privileges to cause a
    denial of service via a crafted system call to the KVM
    subsystem.(CVE-2018-19407)It was found that current
    implementation of kl5kusb105 driver failed to detect
    short transfers when attempting to read the line state
    and logged the content of the uninitialized heap
    transfer buffer.(CVE-2017-5549)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e5b5599");
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
