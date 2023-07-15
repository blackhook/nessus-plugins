#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124971);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2013-2897",
    "CVE-2014-1739",
    "CVE-2014-3144",
    "CVE-2014-3153",
    "CVE-2014-3646",
    "CVE-2015-0239",
    "CVE-2015-1339",
    "CVE-2015-1350",
    "CVE-2015-3290",
    "CVE-2015-7885",
    "CVE-2015-8539",
    "CVE-2016-5412",
    "CVE-2016-8660",
    "CVE-2016-9083",
    "CVE-2016-9755",
    "CVE-2017-15127",
    "CVE-2017-2596",
    "CVE-2018-16597",
    "CVE-2018-16658",
    "CVE-2018-17972"
  );
  script_bugtraq_id(
    62044,
    67309,
    67906,
    68048,
    70745,
    72842,
    76004
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1518)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Linux kernel built with the KVM visualization support
    (CONFIG_KVM), with nested visualization(nVMX) feature
    enabled(nested=1), is vulnerable to host memory leakage
    issue. It could occur while emulating VMXON instruction
    in 'handle_vmon'. An L1 guest user could use this flaw
    to leak host memory potentially resulting in
    DoS.(CVE-2017-2596i1/4%0

  - The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST
    extension implementations in the sk_run_filter function
    in net/core/filter.c in the Linux kernel through 3.14.3
    do not check whether a certain length value is
    sufficiently large, which allows local users to cause a
    denial of service (integer underflow and system crash)
    via crafted BPF instructions. NOTE: the affected code
    was moved to the __skb_get_nlattr and
    __skb_get_nlattr_nest functions before the
    vulnerability was announced.(CVE-2014-3144i1/4%0

  - A flaw was found in the Linux kernel when freeing pages
    in hugetlbfs. This could trigger a local denial of
    service by crashing the kernel.(CVE-2017-15127i1/4%0

  - An issue was discovered in the Linux kernel before 4.8.
    Incorrect access checking in overlayfs mounts could be
    used by local attackers to modify or truncate files in
    the underlying filesystem.(CVE-2018-16597i1/4%0

  - Memory leak in the cuse_channel_release function in
    fs/fuse/cuse.c in the Linux kernel before 4.4 allows
    local users to cause a denial of service (memory
    consumption) or possibly have unspecified other impact
    by opening /dev/cuse many times.(CVE-2015-1339i1/4%0

  - A flaw was found in the way the Linux kernel's nested
    NMI handler and espfix64 functionalities interacted
    during NMI processing. A local, unprivileged user could
    use this flaw to crash the system or, potentially,
    escalate their privileges on the
    system.(CVE-2015-3290i1/4%0

  - Multiple array index errors in
    drivers/hid/hid-multitouch.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through
    3.11, when CONFIG_HID_MULTITOUCH is enabled, allow
    physically proximate attackers to cause a denial of
    service (heap memory corruption, or NULL pointer
    dereference and OOPS) via a crafted
    device.(CVE-2013-2897i1/4%0

  - A flaw was found in the way the Linux kernel's futex
    subsystem handled the requeuing of certain Priority
    Inheritance (PI) futexes. A local, unprivileged user
    could use this flaw to escalate their privileges on the
    system.(CVE-2014-3153i1/4%0

  - The XFS subsystem in the Linux kernel 4.4 and later
    allows local users to cause a denial of service
    (fdatasync() failure and system hang) by using the vfs
    syscall group in the 'trinity' program, as a result of
    a page lock order bug in the XFS seek hole/data
    implementation.(CVE-2016-8660i1/4%0

  - A flaw was found in the Linux kernel's key management
    system where it was possible for an attacker to
    escalate privileges or crash the machine. If a user key
    gets negatively instantiated, an error code is cached
    in the payload area. A negatively instantiated key may
    be then be positively instantiated by updating it with
    valid data. However, the -i1/4zupdate key type method
    must be aware that the error code may be
    there.(CVE-2015-8539i1/4%0

  - It was found that the Linux kernel KVM subsystem's
    sysenter instruction emulation was not sufficient. An
    unprivileged guest user could use this flaw to escalate
    their privileges by tricking the hypervisor to emulate
    a SYSENTER instruction in 16-bit mode, if the guest OS
    did not initialize the SYSENTER model-specific
    registers (MSRs). Note: Certified guest operating
    systems for Red Hat Enterprise Linux with KVM do
    initialize the SYSENTER MSRs and are thus not
    vulnerable to this issue when running on a KVM
    hypervisor.(CVE-2015-0239i1/4%0

  - An information leak flaw was found in the way the Linux
    kernel handled media device enumerate entities IOCTL
    requests. A local user able to access the /dev/media0
    device file could use this flaw to leak kernel memory
    bytes.(CVE-2014-1739i1/4%0

  - The dgnc_mgmt_ioctl function in
    drivers/staging/dgnc/dgnc_mgmt.c in the Linux kernel
    through 4.3.3 does not initialize a certain structure
    member, which allows local users to obtain sensitive
    information from kernel memory via a crafted
    application.(CVE-2015-7885i1/4%0

  - An information leak was discovered in the Linux kernel
    in cdrom_ioctl_drive_status() function in
    drivers/cdrom/cdrom.c that could be used by local
    attackers to read kernel memory at certain
    location.(CVE-2018-16658i1/4%0

  - A flaw was discovered in the Linux kernel's
    implementation of VFIO. An attacker issuing an ioctl
    can create a situation where memory is corrupted and
    modify memory outside of the expected area. This may
    overwrite kernel memory and subvert kernel
    execution.(CVE-2016-9083i1/4%0

  - It was found that the Linux kernel's KVM subsystem did
    not handle the VM exits gracefully for the invvpid
    (Invalidate Translations Based on VPID) instructions.
    On hosts with an Intel processor and invppid VM exit
    support, an unprivileged guest user could use these
    instructions to crash the guest.(CVE-2014-3646i1/4%0

  - An attacker on a network could abuse a flaw in the IPv6
    stack fragment reassembly code to induce kernel memory
    corruption on the system, possibly leading to a system
    crash.(CVE-2016-9755i1/4%0

  - It was found that a regular user could remove xattr
    permissions on files by using the chown or write system
    calls. A local attacker could use this flaw to deny
    elevated permissions from valid users, services, or
    applications, potentially resulting in a denial of
    service.(CVE-2015-1350i1/4%0

  - arch/powerpc/kvm/book3s_hv_rmhandlers.S in the Linux
    kernel through 4.7 on PowerPC platforms, when
    CONFIG_KVM_BOOK3S_64_HV is enabled, allows guest OS
    users to cause a denial of service (host OS infinite
    loop) by making a H_CEDE hypercall during the existence
    of a suspended transaction.(CVE-2016-5412i1/4%0

  - An issue was discovered in the proc_pid_stack function
    in fs/proc/base.c in the Linux kernel. An attacker with
    a local account can trick the stack unwinder code to
    leak stack contents to userspace. The fix allows only
    root to inspect the kernel stack of an arbitrary
    task.(CVE-2018-17972i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1518
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fa3dae4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9083");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-9755");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Towelroot Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
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
