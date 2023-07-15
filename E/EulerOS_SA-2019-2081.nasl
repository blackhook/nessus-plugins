#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129440);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-13648",
    "CVE-2019-14284",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15030",
    "CVE-2019-15031",
    "CVE-2019-15090",
    "CVE-2019-15117",
    "CVE-2019-15212",
    "CVE-2019-15213",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15918",
    "CVE-2019-15922",
    "CVE-2019-15923",
    "CVE-2019-15924",
    "CVE-2019-15926"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2019-2081)");
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
    the Linux kernel before 5.1.8. There is a double-free
    caused by a malicious USB device in the
    drivers/usb/misc/rio500.c driver.(CVE-2019-15212)An
    issue was discovered in the Linux kernel before 5.2.3.
    There is a use-after-free caused by a malicious USB
    device in the drivers/media/usb/dvb-usb/dvb-usb-init.c
    driver.(CVE-2019-15213)An issue was discovered in the
    Linux kernel before 5.2.6. There is a use-after-free
    caused by a malicious USB device in the
    drivers/media/usb/cpia2/cpia2_usb.c
    driver.(CVE-2019-15215)An issue was discovered in the
    Linux kernel before 5.0.14. There is a NULL pointer
    dereference caused by a malicious USB device in the
    drivers/usb/misc/yurex.c driver.(CVE-2019-15216)An
    issue was discovered in the Linux kernel before 5.2.3.
    There is a NULL pointer dereference caused by a
    malicious USB device in the
    drivers/media/usb/zr364xx/zr364xx.c
    driver.(CVE-2019-15217)An issue was discovered in
    drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before
    5.1.12. In the qedi_dbg_* family of functions, there is
    an out-of-bounds read.(CVE-2019-15090)In the Linux
    kernel through 5.2.14 on the powerpc platform, a local
    user can read vector registers of other users'
    processes via a Facility Unavailable exception. To
    exploit the venerability, a local user starts a
    transaction (via the hardware transactional memory
    instruction tbegin) and then accesses vector registers.
    At some point, the vector registers will be corrupted
    with the values from a different local Linux process
    because of a missing arch/powerpc/kernel/process.c
    check.(CVE-2019-15030)In the Linux kernel through
    5.2.14 on the powerpc platform, a local user can read
    vector registers of other users' processes via an
    interrupt. To exploit the venerability, a local user
    starts a transaction (via the hardware transactional
    memory instruction tbegin) and then accesses vector
    registers. At some point, the vector registers will be
    corrupted with the values from a different local Linux
    process, because MSR_TM_ACTIVE is misused in
    arch/powerpc/kernel/process.c.(CVE-2019-15031)An
    out-of-bounds access issue was found in the Linux
    kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO
    write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write
    indices 'ring-i1/4zfirst' and 'ring-i1/4zlast' value could
    be supplied by a host user-space process. An
    unprivileged host user or process with access to
    '/dev/kvm' device could use this flaw to crash the host
    kernel, resulting in a denial of service or potentially
    escalating privileges on the system.(CVE-2019-14821)A
    buffer overflow flaw was found, in versions from 2.6.34
    to 5.2.x, in the way Linux kernel's vhost functionality
    that translates virtqueue buffers to IOVs, logged the
    buffer descriptors during migration. A privileged guest
    user able to pass descriptors with invalid length to
    the host when migration is underway, could use this
    flaw to increase their privileges on the
    host.(CVE-2019-14835)An issue was discovered in the
    Linux kernel before 5.0.9. There is a NULL pointer
    dereference for a pf data structure if alloc_disk fails
    in drivers/block/paride/pf.c.(CVE-2019-15922)An issue
    was discovered in the Linux kernel before 5.0.10.
    SMB2_negotiate in fs/cifs/smb2pdu.c has an
    out-of-bounds read because data structures are
    incompletely updated after a change from smb30 to
    smb21.(CVE-2019-15918)An issue was discovered in the
    Linux kernel before 5.0.9. There is a NULL pointer
    dereference for a cd data structure if alloc_disk fails
    in drivers/block/paride/pf.c.(CVE-2019-15923)An issue
    was discovered in the Linux kernel before 5.0.11.
    fm10k_init_module in drivers
    et/ethernet/intel/fm10k/fm10k_main.c has a NULL pointer
    dereference because there is no -ENOMEM upon an
    alloc_workqueue failure.(CVE-2019-15924)An issue was
    discovered in the Linux kernel before 5.2.3. Out of
    bounds access exists in the functions
    ath6kl_wmi_pstream_timeout_event_rx and
    ath6kl_wmi_cac_event_rx in the file
    driverset/wireless/ath/ath6kl/wmi.c.(CVE-2019-15926)par
    se_audio_mixer_unit in sound/usb/mixer.c in the Linux
    kernel through 5.2.9 mishandles a short descriptor,
    leading to out-of-bounds memory
    access.(CVE-2019-15117)In the Linux kernel before
    5.2.3, drivers/block/floppy.c allows a denial of
    service by setup_format_params division-by-zero. Two
    consecutive ioctls can trigger the bug: the first one
    should set the drive geometry with .sect and .rate
    values that make F_SECT_PER_TRACK be zero. Next, the
    floppy format operation should be called. It can be
    triggered by an unprivileged local user even when a
    floppy disk has not been inserted. NOTE: QEMU creates
    the floppy device by default.(CVE-2019-14284)In the
    Linux kernel through 5.2.1 on the powerpc platform,
    when hardware transactional memory is disabled, a local
    user can cause a denial of service (TM Bad Thing
    exception and system crash) via a sigreturn() system
    call that sends a crafted signal frame. This affects
    arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c.(CVE-2019-13648)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2081
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06ead936");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h453.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h453.eulerosv2r8"];

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
