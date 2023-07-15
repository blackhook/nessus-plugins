#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128842);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-10323",
    "CVE-2018-10879",
    "CVE-2018-10883",
    "CVE-2018-13406",
    "CVE-2018-15594",
    "CVE-2018-16871",
    "CVE-2018-20856",
    "CVE-2019-12378",
    "CVE-2019-12381",
    "CVE-2019-12382",
    "CVE-2019-12614",
    "CVE-2019-13631",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14284"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1919)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The xfs_bmap_extents_to_btree function in
    fs/xfs/libxfs/xfs_bmap.c in the Linux kernel through
    4.16.3 allows local users to cause a denial of service
    (xfs_bmapi_write NULL pointer dereference) via a
    crafted xfs image.(CVE-2018-10323)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause a use-after-free in
    ext4_xattr_set_entry function and a denial of service
    or unspecified other impact may occur by renaming a
    file in a crafted ext4 filesystem
    image.(CVE-2018-10879)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in
    jbd2_journal_dirty_metadata(), a denial of service, and
    a system crash by mounting and operating on a crafted
    ext4 filesystem image. (CVE-2018-10883)

  - The Linux kernel was found vulnerable to an integer
    overflow in the
    drivers/video/fbdev/uvesafb.c:uvesafb_setcmap()
    function. The vulnerability could result in local
    attackers being able to crash the kernel or potentially
    elevate privileges.(CVE-2018-13406)

  - It was found that paravirt_patch_call/jump() functions
    in the arch/x86/kernel/paravirt.c in the Linux kernel
    mishandles certain indirect calls, which makes it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtualized guests. (CVE-2018-15594)

  - A flaw was found in the Linux kernel's NFS
    implementation. An attacker, who is able to mount an
    exported NFS filesystem, is able to trigger a null
    pointer dereference by using an invalid NFS sequence.
    This can panic the machine and deny access to the NFS
    server. Any outstanding disk writes to the NFS server
    will be lost. (CVE-2018-16871)

  - A vulnerability was found in the Linux kernelaEURtms
    floppy disk driver implementation. A local attacker
    with access to the floppy device could call
    set_geometry in drivers/block/floppy.c, which does not
    validate the sect and head fields, causing an integer
    overflow and out-of-bounds read. This flaw may crash
    the system or allow an attacker to gather information
    causing subsequent successful attacks. (CVE-2019-14283)

  - A vulnerability was found in the Linux kernelaEURtms
    floppy disk driver implementation. A local attacker
    with access to the floppy disk device file (/dev/fd0
    through to /dev/fdN) can create a situation that causes
    the kernel to divide by zero. This requires two
    consecutive ioctl calls to be issued. The first ioctl
    call sets the sector and rate values, and the second
    ioctl is the call to format the floppy disk to the
    appropriate values. This flaw can cause the system to
    divide by zero and panic the host. No media (floppy) is
    required to be inserted for this attack to work
    properly.(CVE-2019-14284)

  - In the Linux kernel through 5.2.1 on the powerpc
    platform, when hardware transactional memory is
    disabled, a local user can cause a denial of service
    (TM Bad Thing exception and system crash) via a
    sigreturn() system call that sends a crafted signal
    frame. This affects arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c.(CVE-2019-13648)

  - In parse_hid_report_descriptor in
    drivers/input/tablet/gtco.c in the Linux kernel through
    5.2.1, a malicious USB device can send an HID report
    that triggers an out-of-bounds write during generation
    of debugging messages. (CVE-2019-13631)

  - An issue was discovered in drm_load_edid_firmware in
    drivers/gpu/drm/drm_edid_load.c in the Linux kernel
    through 5.1.5. There is an unchecked kstrdup of fwstr,
    which might allow an attacker to cause a denial of
    service (NULL pointer dereference and system crash).
    NOTE: The vendor disputes this issues as not being a
    vulnerability because kstrdup() returning NULL is
    handled sufficiently and there is no chance for a NULL
    pointer dereference. (CVE-2019-12382)

  - An issue was discovered in dlpar_parse_cc_property in
    arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of
    prop-i1/4zname, which might allow an attacker to cause a
    denial of service (NULL pointer dereference and system
    crash). (CVE-2019-12614)

  - An issue was discovered in the Linux kernel before
    4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain
    error case is mishandled.(CVE-2018-20856)

  - An issue was discovered in ip_ra_control in
    net/ipv4/ip_sockglue.c in the Linux kernel through
    5.1.5. There is an unchecked kmalloc of new_ra, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system crash). NOTE: this
    is disputed because new_ra is never used if it is
    NULL.(CVE-2019-12381)

  - An issue was discovered in ip6_ra_control in
    net/ipv6/ipv6_sockglue.c in the Linux kernel through
    5.1.5. There is an unchecked kmalloc of new_ra, which
    might allow an attacker to cause a denial of service
    (NULL pointer dereference and system crash). NOTE: This
    has been disputed as not an issue.(CVE-2019-12378)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1919
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fdbaa67");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13406");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "perf-3.10.0-862.14.1.2.h239.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.2.h239.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
