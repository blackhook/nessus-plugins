#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124976);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-2899",
    "CVE-2014-3601",
    "CVE-2014-6410",
    "CVE-2015-0572",
    "CVE-2015-8709",
    "CVE-2015-8953",
    "CVE-2016-10150",
    "CVE-2016-3841",
    "CVE-2016-4805",
    "CVE-2016-9120",
    "CVE-2017-10663",
    "CVE-2017-11473",
    "CVE-2017-12168",
    "CVE-2017-12193",
    "CVE-2017-14489",
    "CVE-2017-16644",
    "CVE-2017-16648",
    "CVE-2017-7533",
    "CVE-2017-9985",
    "CVE-2018-10879"
  );
  script_bugtraq_id(
    62046,
    69489,
    69799
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1523)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The snd_msndmidi_input_read function in
    sound/isa/msnd/msnd_midi.c in the Linux kernel through
    4.11.7 allows local users to cause a denial of service
    (over-boundary access) or possibly have unspecified
    other impact by changing the value of a message queue
    head pointer between two kernel reads of that value,
    aka a 'double fetch' vulnerability.(CVE-2017-9985i1/4%0

  - An assertion failure issue was found in the Linux
    kernel's KVM hypervisor module built to support
    visualization on ARM64 architecture platforms. The
    failure could occur while accessing Performance
    Monitors Cycle Count Register (PMCCNTR) from a guest. A
    privileged guest user could use this flaw to crash the
    host kernel resulting in denial of
    service.(CVE-2017-12168i1/4%0

  - The iscsi_if_rx() function in
    'drivers/scsi/scsi_transport_iscsi.c' in the Linux
    kernel from v2.6.24-rc1 through 4.13.2 allows local
    users to cause a denial of service (a system panic) by
    making a number of certain syscalls by leveraging
    incorrect length validation in the kernel
    code.(CVE-2017-14489i1/4%0

  - The hdpvr_probe function in
    drivers/media/usb/hdpvr/hdpvr-core.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (improper error handling and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16644i1/4%0

  - The dvb frontend management subsystem in the Linux
    kernel contains a use-after-free which can allow a
    malicious user to write to memory that may be assigned
    to another kernel structure. This could create memory
    corruption, panic, or possibly other side
    affects.(CVE-2017-16648i1/4%0

  - It was found that the Linux kernel's IPv6
    implementation mishandled socket options. A local
    attacker could abuse concurrent access to the socket
    options to escalate their privileges, or cause a denial
    of service (use-after-free and system crash) via a
    crafted sendmsg system call.(CVE-2016-3841i1/4%0

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service
    or unspecified other impact may occur by renaming a
    file in a crafted ext4 filesystem
    image.(CVE-2018-10879i1/4%0

  - A race condition was found in the Linux kernel, present
    since v3.14-rc1 through v4.12. The race happens between
    threads of inotify_handle_event() and vfs_rename()
    while running the rename operation against the same
    file. As a result of the race the next slab data or the
    slab's free list pointer can be corrupted with
    attacker-controlled data, which may lead to the
    privilege escalation.(CVE-2017-7533i1/4%0

  - A privilege-escalation vulnerability was discovered in
    the Linux kernel built with User Namespace
    (CONFIG_USER_NS) support. The flaw occurred when the
    ptrace() system call was used on a root-owned process
    to enter a user namespace. A privileged namespace user
    could exploit this flaw to potentially escalate their
    privileges on the system, outside the original
    namespace.(CVE-2015-8709i1/4%0

  - Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    before 4.5.2 allows local users to cause a denial of
    service (memory corruption and system crash, or
    spinlock) or possibly have unspecified other impact by
    removing a network namespace, related to the
    ppp_register_net_channel and ppp_unregister_channel
    functions.(CVE-2016-4805i1/4%0

  - A flaw was found in the way the Linux kernel's
    kvm_iommu_map_pages() function handled IOMMU mapping
    failures. A privileged user in a guest with an assigned
    host device could use this flaw to crash the
    host.(CVE-2014-3601i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of associative arrays introduced in 3.13. This
    functionality was backported to the 3.10 kernels in Red
    Hat Enterprise Linux 7. The flaw involved a null
    pointer dereference in assoc_array_apply_edit() due to
    incorrect node-splitting in assoc_array implementation.
    This affects the keyring key type and thus key addition
    and link creation operations may cause the kernel to
    panic.(CVE-2017-12193i1/4%0

  - Multiple race conditions in drivers/char/adsprpc.c and
    drivers/char/adsprpc_compat.c in the ADSPRPC driver for
    the Linux kernel 3.x, as used in Qualcomm Innovation
    Center (QuIC) Android contributions for MSM devices and
    other products, allow attackers to cause a denial of
    service (zero-value write) or possibly have unspecified
    other impact via a COMPAT_FASTRPC_IOCTL_INVOKE_FD ioctl
    call.(CVE-2015-0572i1/4%0

  - The sanity_check_ckpt function in fs/f2fs/super.c in
    the Linux kernel before version 4.12.4 does not
    validate the blkoff and segno arrays. This allows an
    unprivileged, local user to cause a system panic and
    DoS. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2017-10663i1/4%0

  - A stack overflow flaw caused by infinite recursion was
    found in the way the Linux kernel's Universal Disk
    Format (UDF) file system implementation processed
    indirect Information Control Blocks (ICBs). An attacker
    with physical access to the system could use a
    specially crafted UDF image to crash the
    system.(CVE-2014-6410i1/4%0

  - Race condition in the ion_ioctl function in
    drivers/staging/android/ion/ion.c in the Linux kernel
    before 4.6 allows local users to gain privileges or
    cause a denial of service (use-after-free) by calling
    ION_IOC_FREE on two CPUs at the same
    time.(CVE-2016-9120i1/4%0

  - drivers/hid/hid-picolcd_core.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_PICOLCD is enabled, allows
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and OOPS) via a
    crafted device.(CVE-2013-2899i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of overlayfs. An attacker can leak file resources in
    the system by opening a large file with write
    permissions on a overlay filesystem that is
    insufficient to deal with the size of the write.When
    unmounting the underlying device, the system is unable
    to free an inode and this will consume resources.
    Repeating this for all available inodes and memory will
    create a denial of service situation.(CVE-2015-8953i1/4%0

  - Buffer overflow in the mp_override_legacy_irq()
    function in arch/x86/kernel/acpi/boot.c in the Linux
    kernel through 4.12.2 allows local users to gain
    privileges via a crafted ACPI table.(CVE-2017-11473i1/4%0

  - Use-after-free vulnerability in the
    kvm_ioctl_create_device function in virt/kvm/kvm_main.c
    in the Linux kernel before 4.8.13 allows host OS users
    to cause a denial of service (host OS crash) or
    possibly gain privileges via crafted ioctl calls on the
    /dev/kvm device.(CVE-2016-10150i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ab359ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
