#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124828);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2014-3184",
    "CVE-2014-3534",
    "CVE-2014-4608",
    "CVE-2014-8481",
    "CVE-2014-9904",
    "CVE-2015-3288",
    "CVE-2015-7990",
    "CVE-2015-8660",
    "CVE-2016-10044",
    "CVE-2016-3955",
    "CVE-2016-6828",
    "CVE-2017-1000405",
    "CVE-2017-15128",
    "CVE-2017-17450",
    "CVE-2017-18232",
    "CVE-2017-18257",
    "CVE-2017-7374",
    "CVE-2018-20169",
    "CVE-2018-5391",
    "CVE-2018-7740"
  );
  script_bugtraq_id(
    68214,
    68940,
    69768,
    70712
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1505)");
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
    output, etc.Security Fix(es):A flaw named FragmentSmack
    was found in the way the Linux kernel handled
    reassembly of fragmented IPv4 and IPv6 packets. A
    remote attacker could use this flaw to trigger time and
    calculation expensive fragment reassembly algorithm by
    sending specially crafted packets which could lead to a
    CPU saturation and hence a denial of service on the
    system.(CVE-2018-5391)Multiple out-of-bounds write
    flaws were found in the way the Cherry Cymotion
    keyboard driver, KYE/Genius device drivers, Logitech
    device drivers, Monterey Genius KB29E keyboard driver,
    Petalynx Maxter remote control driver, and Sunplus
    wireless desktop driver handled HID reports with an
    invalid report descriptor size. An attacker with
    physical access to the system could use either of these
    flaws to write data past an allocated memory
    buffer.(CVE-2014-3184)The __get_data_block function in
    fs/f2fs/data.c in the Linux kernel before 4.11 allows
    local users to cause a denial of service (integer
    overflow and loop) via crafted use of the open and
    fallocate system calls with an FS_IOC_FIEMAP
    ioctl.(CVE-2017-18257)netetfilter/xt_osf.c in the Linux
    kernel through 4.14.4 does not require the
    CAP_NET_ADMIN capability for add_callback and
    remove_callback operations. This allows local users to
    bypass intended access restrictions because the
    xt_osf_fingers data structure is shared across all
    network namespaces.(CVE-2017-17450)A denial of service
    flaw was discovered in the Linux kernel, where a race
    condition caused a NULL pointer dereference in the RDS
    socket-creation code. A local attacker could use this
    flaw to create a situation in which a NULL pointer
    crashed the kernel.(CVE-2015-7990)An issue was
    discovered in the Linux kernel before 4.19.9. The USB
    subsystem mishandles size checks during the reading of
    an extra descriptor, related to
    __usb_get_extra_descriptor in
    drivers/usb/core/usb.c.(CVE-2018-20169)mm/memory.c in
    the Linux kernel before 4.1.4 mishandles anonymous
    pages, which allows local users to gain privileges or
    cause a denial of service (page tainting) via a crafted
    application that triggers writing to page
    zero.(CVE-2015-3288)The ovl_setattr function in
    fs/overlayfs/inode.c in the Linux kernel through 4.3.3
    attempts to merge distinct setattr operations, which
    allows local users to bypass intended access
    restrictions and modify the attributes of arbitrary
    overlay files via a crafted
    application.(CVE-2015-8660)A flaw was found in the
    Linux kernel where a local user with a shell account
    can abuse the userfaultfd syscall when using hugetlbfs.
    A missing size check in hugetlb_mcopy_atomic_pte could
    create an invalid inode variable, leading to a kernel
    panic.(CVE-2017-15128)An integer overflow flaw was
    found in the way the lzo1x_decompress_safe() function
    of the Linux kernel's LZO implementation processed
    Literal Runs. A local attacker could, in extremely rare
    cases, use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-4608)It was found that Linux kernel's
    ptrace subsystem did not properly sanitize the
    address-space-control bits when the program-status word
    (PSW) was being set. On IBM S/390 systems, a local,
    unprivileged user could use this flaw to set
    address-space-control bits to the kernel space, and
    thus gain read and write access to kernel
    memory.(CVE-2014-3534)A use-after-free flaw was found
    in the Linux kernel's file system encryption
    implementation. A local user could revoke keyring keys
    being used for ext4, f2fs, or ubifs encryption, causing
    a denial of service on the system.(CVE-2017-7374)The
    usbip_recv_xbuff function in
    drivers/usb/usbip/usbip_common.c in the Linux kernel
    before 4.5.3 allows remote attackers to cause a denial
    of service (out-of-bounds write) or possibly have
    unspecified other impact via a crafted length value in
    a USB/IP packet.(CVE-2016-3955)A flaw was found in the
    patches used to fix the 'dirtycow' vulnerability
    (CVE-2016-5195). An attacker, able to run local code,
    can exploit a race condition in transparent huge pages
    to modify usually read-only huge
    pages.(CVE-2017-1000405)The aio_mount function in
    fs/aio.c in the Linux kernel does not properly restrict
    execute access, which makes it easier for local users
    to bypass intended SELinux W^X policy
    restrictions.(CVE-2016-10044)The Serial Attached SCSI
    (SAS) implementation in the Linux kernel mishandles a
    mutex within libsas. This allows local users to cause a
    denial of service (deadlock) by triggering certain
    error-handling code.(CVE-2017-18232)A use-after-free
    vulnerability was found in tcp_xmit_retransmit_queue
    and other tcp_* functions. This condition could allow
    an attacker to send an incorrect selective
    acknowledgment to existing connections, possibly
    resetting a connection.(CVE-2016-6828)The instruction
    decoder in arch/x86/kvm/emulate.c in the KVM subsystem
    in the Linux kernel before 3.18-rc2 does not properly
    handle invalid instructions, which allows guest OS
    users to cause a denial of service (NULL pointer
    dereference and host OS crash) via a crafted
    application that triggers (1) an improperly fetched
    instruction or (2) an instruction that occupies too
    many bytes. NOTE: this vulnerability exists because of
    an incomplete fix for CVE-2014-8480.(CVE-2014-8481)The
    snd_compress_check_input function in
    sound/core/compress_offload.c in the ALSA subsystem in
    the Linux kernel before 3.17 does not properly check
    for an integer overflow, which allows local users to
    cause a denial of service (insufficient memory
    allocation) or possibly have unspecified other impact
    via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl
    call.(CVE-2014-9904)The resv_map_release function in
    mm/hugetlb.c in the Linux kernel, through 4.15.7,
    allows local users to cause a denial of service (BUG)
    via a crafted application that makes mmap system calls
    and has a large pgoff argument to the remap_file_pages
    system call.(CVE-2018-7740)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1505
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dd8d759");
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
  script_set_attribute(attribute:"metasploit_name", value:'Overlayfs Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
