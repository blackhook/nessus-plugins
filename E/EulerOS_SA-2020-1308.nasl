#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134799);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-0154",
    "CVE-2019-14615",
    "CVE-2020-7053",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-8992",
    "CVE-2020-9383"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2020-1308)");

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
    output, etc.Security
    Fix(es):ext4_protect_reserved_inode in
    fs/ext4/block_validity.c in the Linux kernel through
    5.5.3 allows attackers to cause a denial of service
    (soft lockup) via a crafted journal
    size.(CVE-2020-8992)An issue was discovered in the
    Linux kernel through 5.5.6. set_fdc in
    drivers/block/floppy.c leads to a wait_til_ready
    out-of-bounds read because the FDC index is not checked
    for errors before assigning it, aka
    CID-2e90ca68b0d2.(CVE-2020-9383)There is a
    use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the vgacon_invert_region function in
    drivers/video/console/vgacon.c.(CVE-2020-8649)There is
    a use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c.(CVE-2020-8647)Insufficient access
    control in subsystem for Intel (R) processor graphics
    in 6th, 7th, 8th and 9th Generation Intel(R) Core(TM)
    Processor Families Intel(R) Pentium(R) Processor J, N,
    Silver and Gold Series Intel(R) Celeron(R) Processor J,
    N, G3900 and G4900 Series Intel(R) Atom(R) Processor A
    and E3900 Series Intel(R) Xeon(R) Processor E3-1500 v5
    and v6 and E-2100 Processor Families may allow an
    authenticated user to potentially enable denial of
    service via local access.(CVE-2019-0154)There is a
    use-after-free vulnerability in the Linux kernel
    through 5.5.2 in the n_tty_receive_buf_common function
    in drivers/tty_tty.c.(CVE-2020-8648)In the Linux kernel
    4.14 longterm through 4.14.165 and 4.19 longterm
    through 4.19.96 (and 5.x before 5.2), there is a
    use-after-free (write) in the i915_ppgtt_close function
    in drivers/gpu/drm/i915/i915_gem_gtt.c, aka
    CID-7dc40713618c. This is related to
    i915_gem_context_destroy_ioctl in
    drivers/gpu/drm/i915/i915_gem_context.c.(CVE-2020-7053)
    Insufficient control flow in certain data structures
    for some Intel(R) Processors with Intel(R) Processor
    Graphics may allow an unauthenticated user to
    potentially enable information disclosure via local
    access.(CVE-2019-14615)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1308
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e60e265");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7053");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/23");

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

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h428.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h428.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
