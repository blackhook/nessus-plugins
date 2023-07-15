#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134784);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-19447",
    "CVE-2019-19768",
    "CVE-2019-19807",
    "CVE-2019-3016",
    "CVE-2020-2732",
    "CVE-2020-8428",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2020-1292)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In the Linux kernel 5.0.21, mounting a crafted ext4
    filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in
    ext4_put_super in fs/ext4/super.c, related to
    dump_orphan_list in fs/ext4/super.c.(CVE-2019-19447 )

  - In the Linux kernel 5.4.0-rc2, there is a
    use-after-free (read) in the __blk_add_trace function
    in kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu
    sub-buffer).(CVE-2019-19768)

  - ext4_protect_reserved_inode in fs/ext4/block_validity.c
    in the Linux kernel through 5.5.3 allows attackers to
    cause a denial of service (soft lockup) via a crafted
    journal size.(CVE-2020-8992)

  - An issue was discovered in the Linux kernel through
    5.5.6. set_fdc in drivers/block/floppy.c leads to a
    wait_til_ready out-of-bounds read because the FDC index
    is not checked for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)

  - In the Linux kernel before 5.3.11, sound/core/timer.c
    has a use-after-free caused by erroneous code
    refactoring, aka CID-e7af6307a8a5. This is related to
    snd_timer_open and snd_timer_close_locked. The timeri
    variable was originally intended to be for a newly
    created timer instance, but was used for a different
    purpose after refactoring.(CVE-2019-19807)

  - Kernel: kvm: nVMX: L2 guest may trick the L0 hypervisor
    to access sensitive L1 resources(CVE-2020-2732)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c.(CVE-2020-8648)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vgacon_invert_region
    function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)

  - There is a use-after-free vulnerability in the Linux
    kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)

  - fs/namei.c in the Linux kernel before 5.5 has a
    may_create_in_sticky use-after-free, which allows local
    users to cause a denial of service (OOPS) or possibly
    obtain sensitive information from kernel memory, aka
    CID-d0cb50185ae9. One attack vector may be an open
    system call for a UNIX domain socket, if the socket is
    being moved to a new parent directory and its old
    parent directory is being removed.(CVE-2020-8428)

  - In a Linux KVM guest that has PV TLB enabled, a process
    in the guest kernel may be able to read memory
    locations from another process in the same guest. This
    problem is limit to the host running linux kernel 4.10
    with a guest running linux kernel 4.16 or later. The
    problem mainly affects AMD processors but Intel CPUs
    cannot be ruled out.(CVE-2019-3016)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb4d37a7");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/23");

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

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h702.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h702.eulerosv2r8"];

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
