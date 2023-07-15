#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124982);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-2888",
    "CVE-2013-2893",
    "CVE-2013-6376",
    "CVE-2013-7268",
    "CVE-2014-1438",
    "CVE-2014-1445",
    "CVE-2014-6417",
    "CVE-2014-7842",
    "CVE-2014-8884",
    "CVE-2015-3291",
    "CVE-2015-4170",
    "CVE-2015-8746",
    "CVE-2016-5195",
    "CVE-2016-5400",
    "CVE-2016-10147",
    "CVE-2017-9242",
    "CVE-2017-12188",
    "CVE-2017-14140",
    "CVE-2017-16527",
    "CVE-2017-16528"
  );
  script_bugtraq_id(
    62043,
    62050,
    64319,
    64741,
    64781,
    64953,
    70395,
    71078,
    71097,
    76003
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1529)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The ipx_recvmsg function in net/ipx/af_ipx.c in the
    Linux kernel before 3.12.4 updates a certain length
    value without ensuring that an associated data
    structure has been initialized, which allows local
    users to obtain sensitive information from kernel
    memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
    system call.(CVE-2013-7268i1/4%0

  - The move_pages system call in mm/migrate.c in the Linux
    kernel doesn't check the effective uid of the target
    process. This enables a local attacker to learn the
    memory layout of a setuid executable allowing
    mitigation of ASLR.(CVE-2017-14140i1/4%0

  - Multiple array index errors in drivers/hid/hid-core.c
    in the Human Interface Device (HID) subsystem in the
    Linux kernel through 3.11 allow physically proximate
    attackers to execute arbitrary code or cause a denial
    of service (heap memory corruption) via a crafted
    device that provides an invalid Report
    ID.(CVE-2013-2888i1/4%0

  - It was found that if a Non-Maskable Interrupt (NMI)
    occurred immediately after a SYSCALL call or before a
    SYSRET call with the user RSP pointing to the NMI IST
    stack, the kernel could skip that NMI.(CVE-2015-3291i1/4%0

  - The sound/core/seq_device.c in the Linux kernel, before
    4.13.4, allows local users to cause a denial of service
    (snd_rawmidi_dev_seq_free use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16528i1/4%0

  - net/ceph/auth_x.c in Ceph, as used in the Linux kernel
    before 3.16.3, does not properly consider the
    possibility of kmalloc failure, which allows remote
    attackers to cause a denial of service (system crash)
    or possibly have unspecified other impact via a long
    unencrypted auth ticket.(CVE-2014-6417i1/4%0

  - A NULL pointer dereference flaw was found in the Linux
    kernel: the NFSv4.2 migration code improperly
    initialized the kernel structure. A local,
    authenticated user could use this flaw to cause a panic
    of the NFS client (denial of service).(CVE-2015-8746i1/4%0

  - A stack-based buffer overflow flaw was found in the
    TechnoTrend/Hauppauge DEC USB device driver. A local
    user with write access to the corresponding device
    could use this flaw to crash the kernel or,
    potentially, elevate their privileges on the
    system.(CVE-2014-8884i1/4%0

  - A flaw was found in the linux kernel's implementation
    of the airspy USB device driver in which a leak was
    found when a subdev or SDR are plugged into the host.An
    attacker can create an targeted USB device which can
    emulate 64 of these devices. Then by emulating an
    additional device which continuously connects and
    disconnects, each connection attempt will leak memory
    which can not be recovered.(CVE-2016-5400i1/4%0

  - The sound/usb/mixer.c in the Linux kernel, before
    4.13.8, allows local users to cause a denial of service
    (snd_usb_mixer_interrupt use-after-free and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16527i1/4%0

  - The Human Interface Device (HID) subsystem in the Linux
    kernel through 3.11, when CONFIG_LOGITECH_FF,
    CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled,
    allows physically proximate attackers to cause a denial
    of service (heap-based out-of-bounds write) via a
    crafted device, related to (1) drivers/hid/hid-lgff.c,
    (2) drivers/hid/hid-lg3ff.c, and (3)
    drivers/hid/hid-lg4ff.c.(CVE-2013-2893i1/4%0

  - It was found that reporting emulation failures to user
    space could lead to either a local (CVE-2014-7842) or a
    L2-i1/4zL1 (CVE-2010-5313) denial of service. In the case
    of a local denial of service, an attacker must have
    access to the MMIO area or be able to access an I/O
    port. Please note that on certain systems, HPET is
    mapped to userspace as part of vdso (vvar) and thus an
    unprivileged user may generate MMIO transactions (and
    enter the emulator) this way.(CVE-2014-7842i1/4%0

  - A flaw was discovered in the way the Linux kernel's TTY
    subsystem handled the tty shutdown phase. A local,
    unprivileged user could use this flaw to cause denial
    of service on the system by holding a reference to the
    ldisc lock during tty shutdown, causing a
    deadlock.(CVE-2015-4170i1/4%0

  - The __ip6_append_data function in net/ipv6/ip6_output.c
    in the Linux kernel through 4.11.3 is too late in
    checking whether an overwrite of an skb data structure
    may occur, which allows local users to cause a denial
    of service (system crash) via crafted system
    calls.(CVE-2017-9242i1/4%0

  - The Linux kernel built with the KVM visualization
    support (CONFIG_KVM), with nested visualization(nVMX)
    feature enabled (nested=1), was vulnerable to a stack
    buffer overflow issue. The vulnerability could occur
    while traversing guest page table entries to resolve
    guest virtual address(gva). An L1 guest could use this
    flaw to crash the host kernel resulting in denial of
    service (DoS) or potentially execute arbitrary code on
    the host to gain privileges on the
    system.(CVE-2017-12188i1/4%0

  - The recalculate_apic_map function in
    arch/x86/kvm/lapic.c in the KVM subsystem in the Linux
    kernel through 3.12.5 allows guest OS users to cause a
    denial of service (host OS crash) via a crafted ICR
    write operation in x2apic mode.(CVE-2013-6376i1/4%0

  - The wanxl_ioctl function in drivers/net/wan/wanxl.c in
    the Linux kernel before 3.11.7 does not properly
    initialize a certain data structure, which allows local
    users to obtain sensitive information from kernel
    memory via an ioctl call.(CVE-2014-1445i1/4%0

  - The restore_fpu_checking function in
    arch/x86/include/asm/fpu-internal.h in the Linux kernel
    before 3.12.8 on the AMD K7 and K8 platforms does not
    clear pending exceptions before proceeding to an EMMS
    instruction, which allows local users to cause a denial
    of service (task kill) or possibly gain privileges via
    a crafted application.(CVE-2014-1438i1/4%0

  - A race condition was found in the way the Linux
    kernel's memory subsystem handled the copy-on-write
    (COW) breakage of private read-only memory mappings. An
    unprivileged, local user could use this flaw to gain
    write access to otherwise read-only memory mappings and
    thus increase their privileges on the
    system.(CVE-2016-5195i1/4%0

  - Algorithms not compatible with mcryptd could be spawned
    by mcryptd with a direct crypto_alloc_tfm invocation
    using a 'mcryptd(alg)' name construct. This causes
    mcryptd to crash the kernel if an arbitrary 'alg' is
    incompatible and not intended to be used with
    mcryptd.(CVE-2016-10147i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1529
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b5dd231");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16528");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-12188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

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
