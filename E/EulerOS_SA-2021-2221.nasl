#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151767);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/21");

  script_cve_id(
    "CVE-2020-25672",
    "CVE-2020-27067",
    "CVE-2020-27815",
    "CVE-2020-35519",
    "CVE-2021-20265",
    "CVE-2021-20292",
    "CVE-2021-28964",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29265",
    "CVE-2021-30002",
    "CVE-2021-3428",
    "CVE-2021-3483"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2021-2221)");
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
    output, etc.Security Fix(es):An issue was discovered in
    the Linux kernel before 5.11.3 when a webcam device
    exists. video_usercopy in
    drivers/media/v4l2-core/v4l2-ioctl.c has a memory leak
    for large arguments, aka
    CID-fb18802a338b.(CVE-2021-30002)A flaw was found in
    the JFS filesystem code. This flaw allows a local
    attacker with the ability to set extended attributes to
    panic the system, causing memory corruption or
    escalating privileges. The highest threat from this
    vulnerability is to confidentiality, integrity, as well
    as system availability.(CVE-2020-27815)An out-of-bounds
    (OOB) memory access flaw was found in x25_bind in
    net/x25/af_x25.c in the Linux kernel. A bounds check
    failure allows a local attacker with a user account on
    the system to gain access to out-of-bounds memory,
    leading to a system crash or a leak of internal kernel
    information. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-35519)There is a flaw reported
    in drivers/gpu/drm/ nouveau/ nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)In
    drivers/pci/hotplug/rpadlpar_sysfs.c in the Linux
    kernel through 5.11.8, the RPA PCI Hotplug driver has a
    user-tolerable buffer overflow when writing a new
    device name to the driver from userspace, allowing
    userspace to write data to the kernel stack frame
    directly. This occurs because add_slot_store and
    remove_slot_store mishandle drc_name '\0' termination,
    aka CID-cc7a0bb058b8.(CVE-2021-28972)A race condition
    was discovered in get_old_root in fs/btrfs/ctree.c in
    the Linux kernel through 5.11.8. It allows attackers to
    cause a denial of service (BUG) because of a lack of
    locking on an extent buffer before a cloning operation,
    aka CID-dbcc7d57bffc.(CVE-2021-28964)An issue was
    discovered in the Linux kernel before 5.11.7.
    usbip_sockfd_store in drivers/usb/usbip/stub_dev.c
    allows attackers to cause a denial of service (GPF)
    because the stub-up sequence has race conditions during
    an update of the local and shared status, aka
    CID-9380afd6df70.(CVE-2021-29265)A flaw was found in
    the Linux kernel. A denial of service problem is
    identified if an extent tree is corrupted in a crafted
    ext4 filesystem in fs/ext4/extents.c in
    ext4_es_cache_extent. Fabricating an integer overflow,
    A local attacker with a special user privilege may
    cause a system crash problem which can lead to an
    availability threat.(CVE-2021-3428)BPF JIT compilers in
    the Linux kernel through 5.11.12 have incorrect
    computation of branch displacements, allowing them to
    execute arbitrary code within the kernel context. This
    affects arch/x86/ net/bpf_jit_comp.c and arch/x86/
    net/bpf_jit_comp32.c.(CVE-2021-29154)A flaw was found
    in the way memory resources were freed in the
    unix_stream_recvmsg function in the Linux kernel when a
    signal was pending. This flaw allows an unprivileged
    local user to crash the system by exhausting available
    memory. The highest threat from this vulnerability is
    to system availability.(CVE-2021-20265)In the l2tp
    subsystem, there is a possible use after free due to a
    race condition. This could lead to local escalation of
    privilege with System execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-152409173(CVE-2020-27067)A flaw was found in the Nosy
    driver in the Linux kernel. This issue allows a device
    to be inserted twice into a doubly-linked list, leading
    to a use-after-free when one of these devices is
    removed. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system
    availability.(CVE-2021-3483)kernel: memory leak in
    llcp_sock_connect()(CVE-2020-25672)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58d1e260");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29154");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

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

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h576.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h576.eulerosv2r7"];

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
