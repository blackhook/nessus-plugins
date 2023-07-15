#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133992);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-11135",
    "CVE-2019-14895",
    "CVE-2019-14896",
    "CVE-2019-14897",
    "CVE-2019-16230",
    "CVE-2019-17351",
    "CVE-2019-19048",
    "CVE-2019-19062",
    "CVE-2019-19332",
    "CVE-2019-19338",
    "CVE-2019-19543",
    "CVE-2019-19770",
    "CVE-2019-19922",
    "CVE-2019-19927",
    "CVE-2019-19947",
    "CVE-2019-19965",
    "CVE-2019-19966",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20096",
    "CVE-2019-5108",
    "CVE-2020-7053"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1158)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):In the Linux kernel
    4.19.83, there is a use-after-free (read) in the
    debugfs_remove function in fs/debugfs/inode.c (which is
    used to remove a file or directory in debugfs that was
    previously created with a call to another debugfs
    function such as
    debugfs_create_file).(CVE-2019-19770)mwifiex_tm_cmd in
    driverset/wireless/marvell/mwifiex/cfg80211.c in the
    Linux kernel before 5.1.6 has some error-handling cases
    that did not free allocated hostcmd memory, aka
    CID-003b686ace82. This will cause a memory leak and
    denial of service.(CVE-2019-20095)TSX Asynchronous
    Abort condition on some CPUs utilizing speculative
    execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access.(CVE-2019-11135)A memory leak
    in the crypto_report() function in
    crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering crypto_report_alg()
    failures, aka CID-ffdde5932042.(CVE-2019-19062)In the
    Linux kernel before 5.1.6, there is a use-after-free in
    serial_ir_init_module() in
    drivers/media/rc/serial_ir.c.(CVE-2019-19543)In the
    Linux kernel through 5.4.6, there is a NULL pointer
    dereference in drivers/scsi/libsas/sas_discover.c
    because of mishandling of port disconnection during
    discovery, related to a PHY down race condition, aka
    CID-f70267f379b5.(CVE-2019-19965)In the Linux kernel
    before 5.1.6, there is a use-after-free in cpia2_exit()
    in drivers/media/usb/cpia2/cpia2_v4l.c that will cause
    denial of service, aka
    CID-dea37a972655.(CVE-2019-19966)An issue was
    discovered in drivers/xen/balloon.c in the Linux kernel
    before 5.2.3, as used in Xen through 4.12.x, allowing
    guest OS users to cause a denial of service because of
    unrestricted resource consumption during the mapping of
    guest memory, aka CID-6ef36ab967c7.(CVE-2019-17351)A
    memory leak in the crypto_reportstat() function in
    drivers/virt/vboxguest/vboxguest_utils.c in the Linux
    kernel before 5.3.9 allows attackers to cause a denial
    of service (memory consumption) by triggering
    copy_form_user() failures, aka
    CID-e0b0cb938864.(CVE-2019-19048)kernel/sched/fair.c in
    the Linux kernel before 5.3.9, when cpu.cfs_quota_us is
    used (e.g., with Kubernetes), allows attackers to cause
    a denial of service against non-cpu-bound applications
    by generating a workload that triggers unwanted slice
    expiration, aka CID-de53fd7aedb1. (In other words,
    although this slice expiration would typically be seen
    with benign workloads, it is possible that an attacker
    could calculate how many stray requests are required to
    force an entire Kubernetes cluster into a
    low-performance state caused by slice expiration, and
    ensure that a DDoS attack sent that number of stray
    requests. An attack does not affect the stability of
    the kernel it only causes mismanagement of application
    execution.)(CVE-2019-19922)An out-of-bounds memory
    write issue was found in the Linux Kernel, version 3.13
    through 5.4, in the way the Linux kernel's KVM
    hypervisor handled the 'KVM_GET_EMULATED_CPUID'
    ioctl(2) request to get CPUID features emulated by the
    KVM hypervisor. A user or process able to access the
    '/dev/kvm' device could use this flaw to crash the
    system, resulting in a denial of
    service.(CVE-2019-19332)A flaw was found in the fix for
    CVE-2019-11135, the way Intel CPUs handle speculative
    execution of instructions when a TSX Asynchronous Abort
    (TAA) error occurs. When a guest is running on a host
    CPU affected by the TAA flaw (TAA_NO=0), but is not
    affected by the MDS issue (MDS_NO=1), the guest was to
    clear the affected buffers by using a VERW instruction
    mechanism. But when the MDS_NO=1 bit was exported to
    the guests, the guests did not use the VERW mechanism
    to clear the affected buffers. This issue affects
    guests running on Cascade Lake CPUs and requires that
    host has 'TSX' enabled. Confidentiality of data is the
    highest threat associated with this
    vulnerability.(CVE-2019-19338)In the Linux kernel
    5.0.0-rc7 (as distributed in ubuntu/linux.git on
    kernel.ubuntu.com), mounting a crafted f2fs filesystem
    image and performing some operations can lead to
    slab-out-of-bounds read access in ttm_put_pages in
    drivers/gpu/drm/ttm/ttm_page_alloc.c. This is related
    to the vmwgfx or ttm module.(CVE-2019-19927)In the
    Linux kernel 4.14 longterm through 4.14.165 and 4.19
    longterm through 4.19.96 (and 5.x before 5.2), there is
    a use-after-free (write) in the i915_ppgtt_close
    function in drivers/gpu/drm/i915/i915_gem_gtt.c, aka
    CID-7dc40713618c. This is related to
    i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c.(CVE-2020-7053)
    In the Linux kernel through 5.4.6, there are
    information leaks of uninitialized memory to a USB
    device in the
    driverset/can/usb/kvaser_usb/kvaser_usb_leaf.c driver,
    aka CID-da2311a6385c.(CVE-2019-19947)In the Linux
    kernel before 5.0.6, there is a NULL pointer
    dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka
    CID-23da9588037e.(CVE-2019-20054)In the Linux kernel
    before 5.1, there is a memory leak in
    __feat_register_sp() in net/dccp/feat.c, which may
    cause denial of service, aka
    CID-1d3ff0950e2b.(CVE-2019-20096)A heap-based buffer
    overflow vulnerability was found in the Linux kernel,
    version kernel-2.6.32, in Marvell WiFi chip driver. A
    remote attacker could cause a denial of service (system
    crash) or, possibly execute arbitrary code, when the
    lbs_ibss_join_existing function is called after a STA
    connects to an AP.(CVE-2019-14896)A heap-based buffer
    overflow was discovered in the Linux kernel, all
    versions 3.x.x and 4.x.x before 4.18.0, in Marvell WiFi
    chip driver. The flaw could occur when the station
    attempts a connection negotiation during the handling
    of the remote devices country settings. This could
    allow the remote device to cause a denial of service
    (system crash) or possibly execute arbitrary
    code.(CVE-2019-14895)A stack-based buffer overflow was
    found in the Linux kernel, version kernel-2.6.32, in
    Marvell WiFi chip driver. An attacker is able to cause
    a denial of service (system crash) or, possibly execute
    arbitrary code, when a STA works in IBSS mode (allows
    connecting stations together without the use of an AP)
    and connects to another STA.(CVE-2019-14897)An
    exploitable denial-of-service vulnerability exists in
    the Linux kernel prior to mainline 5.3. An attacker
    could exploit this vulnerability by triggering AP to
    send IAPP location updates for stations before the
    required authentication process has completed. This
    could lead to different denial-of-service scenarios,
    either by causing CAM table attacks, or by leading to
    traffic flapping if faking already existing clients in
    other nearby APs of the same wireless infrastructure.
    An attacker can forge Authentication and Association
    Request packets to trigger this
    vulnerability.(CVE-2019-5108)drivers/gpu/drm/radeon/rad
    eon_display.c in the Linux kernel 5.2.14 does not check
    the alloc_workqueue return value, leading to a NULL
    pointer dereference.(CVE-2019-16230)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1158
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e66e3a3b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h683.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h683.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
