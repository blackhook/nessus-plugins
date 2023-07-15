#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124796);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-2892",
    "CVE-2014-2568",
    "CVE-2014-7843",
    "CVE-2014-9420",
    "CVE-2014-9529",
    "CVE-2014-9730",
    "CVE-2016-2070",
    "CVE-2016-2383",
    "CVE-2016-3134",
    "CVE-2016-4568",
    "CVE-2016-6327",
    "CVE-2016-7915",
    "CVE-2016-9754",
    "CVE-2017-7261",
    "CVE-2017-9605",
    "CVE-2017-16525",
    "CVE-2017-18079",
    "CVE-2017-18204",
    "CVE-2018-1094",
    "CVE-2018-16276"
  );
  script_bugtraq_id(
    62049,
    66348,
    71082,
    71717,
    71880,
    74964
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1472)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The hid_input_field() function in
    'drivers/hid/hid-core.c' in the Linux kernel before 4.6
    allows physically proximate attackers to obtain
    sensitive information from kernel memory or cause a
    denial of service (out-of-bounds read) by connecting a
    device.(CVE-2016-7915i1/4%0

  - The Linux kernel, before version 4.14.2, is vulnerable
    to a deadlock caused by
    fs/ocfs2/file.c:ocfs2_setattr(), as the function does
    not wait for DIO requests before locking the inode.
    This can be exploited by local users to cause a
    subsequent denial of service.(CVE-2017-18204i1/4%0

  - The vmw_gb_surface_define_ioctl function (accessible
    via DRM_IOCTL_VMW_GB_SURFACE_CREATE) in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel through 4.11.4 defines a backup_handle variable
    but does not give it an initial value. If one attempts
    to create a GB surface, with a previously allocated DMA
    buffer to be used as a backup buffer, the backup_handle
    variable does not get written to and is then later
    returned to user space, allowing local users to obtain
    sensitive information from uninitialized kernel memory
    via a crafted ioctl call.(CVE-2017-9605i1/4%0

  - Use-after-free vulnerability in the nfqnl_zcopy
    function in net/netfilter/nfnetlink_queue_core.c in the
    Linux kernel through 3.13.6 allows attackers to obtain
    sensitive information from kernel memory by leveraging
    the absence of a certain orphaning operation. NOTE: the
    affected code was moved to the skb_zerocopy function in
    net/core/skbuff.c before the vulnerability was
    announced.(CVE-2014-2568i1/4%0

  - It was found that the Linux kernel's ISO file system
    implementation did not correctly limit the traversal of
    Rock Ridge extension Continuation Entries (CE). An
    attacker with physical access to the system could use
    this flaw to trigger an infinite loop in the kernel,
    resulting in a denial of service.(CVE-2014-9420i1/4%0

  - An integer overflow vulnerability was found in the
    ring_buffer_resize() calculations in which a privileged
    user can adjust the size of the ringbuffer message
    size. These calculations can create an issue where the
    kernel memory allocator will not allocate the correct
    count of pages yet expect them to be usable. This can
    lead to the ftrace() output to appear to corrupt kernel
    memory and possibly be used for privileged escalation
    or more likely kernel panic.(CVE-2016-9754i1/4%0

  - A symlink size validation was missing in Linux kernels
    built with UDF file system (CONFIG_UDF_FS) support,
    allowing the corruption of kernel memory. An attacker
    able to mount a corrupted/malicious UDF file system
    image could cause the kernel to crash.(CVE-2014-9730i1/4%0

  - In was found that in the Linux kernel, in
    vmw_surface_define_ioctl() function in
    'drivers/gpu/drm/vmwgfx/vmwgfx_surface.c' file, a
    'num_sizes' parameter is assigned a user-controlled
    value which is not checked if it is zero. This is used
    in a call to kmalloc() and later leads to dereferencing
    ZERO_SIZE_PTR, which in turn leads to a GPF and
    possibly to a kernel panic.(CVE-2017-7261i1/4%0

  - A race condition flaw was found in the way the Linux
    kernel keys management subsystem performed key garbage
    collection. A local attacker could attempt accessing a
    key while it was being garbage collected, which would
    cause the system to crash.(CVE-2014-9529i1/4%0

  - A flaw was found in the Linux kernel's implementation
    of i8042 serial ports. An attacker could cause a kernel
    panic if they are able to add and remove devices as the
    module is loaded.(CVE-2017-18079i1/4%0

  - drivers/hid/hid-pl.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_PANTHERLORD is enabled, allows physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted
    device.(CVE-2013-2892i1/4%0

  - The __clear_user function in
    arch/arm64/lib/clear_user.S in the Linux kernel before
    3.17.4 on the ARM64 platform allows local users to
    cause a denial of service (system crash) by reading one
    byte beyond a /dev/zero page boundary.(CVE-2014-7843i1/4%0

  - A divide-by-zero vulnerability was found in a way the
    kernel processes TCP connections. The error can occur
    if a connection starts another cwnd reduction phase by
    setting tp-i1/4zprior_cwnd to the current cwnd (0) in
    tcp_init_cwnd_reduction(). A remote, unauthenticated
    attacker could use this flaw to crash the kernel
    (denial of service).(CVE-2016-2070i1/4%0

  - The adjust_branches function in kernel/bpf/verifier.c
    in the Linux kernel before 4.5 does not consider the
    delta in the backward-jump case, which allows local
    users to obtain sensitive information from kernel
    memory by creating a packet filter and then loading
    crafted BPF instructions.(CVE-2016-2383i1/4%0

  - System using the infiniband support module ib_srpt were
    vulnerable to a denial of service by system crash by a
    local attacker who is able to abort writes to a device
    using this initiator.(CVE-2016-6327i1/4%0

  - A security flaw was found in the Linux kernel in the
    mark_source_chains() function in
    'net/ipv4/netfilter/ip_tables.c'. It is possible for a
    user-supplied 'ipt_entry' structure to have a large
    'next_offset' field. This field is not bounds checked
    prior to writing to a counter value at the supplied
    offset.(CVE-2016-3134i1/4%0

  - An out-of-bounds access issue was discovered in
    yurex_read() in drivers/usb/misc/yurex.c in the Linux
    kernel. A local attacker could use user access
    read/writes with incorrect bounds checking in the yurex
    USB driver to crash the kernel or potentially escalate
    privileges.(CVE-2018-16276i1/4%0

  - drivers/media/v4l2-core/videobuf2-v4l2.c in the Linux
    kernel before 4.5.3 allows local users to cause a
    denial of service (kernel memory write operation) or
    possibly have unspecified other impact via a crafted
    number of planes in a VIDIOC_DQBUF ioctl
    call.(CVE-2016-4568i1/4%0

  - The usb_serial_console_disconnect function in
    drivers/usb/serial/console.c in the Linux kernel,
    before 4.13.8, allows local users to cause a denial of
    service (use-after-free and system crash) or possibly
    have unspecified other impact via a crafted USB device,
    related to disconnection and failed
    setup.(CVE-2017-16525i1/4%0

  - The Linux kernel is vulnerable to a NULL pointer
    dereference in the ext4/xattr.c:ext4_xattr_inode_hash()
    function. An attacker could trick a legitimate user or
    a privileged attacker could exploit this to cause a
    NULL pointer dereference with a crafted ext4 image.
    (CVE-2018-1094)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1472
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?349d271e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16276");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-3134");

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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
