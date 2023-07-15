#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124807);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-7841",
    "CVE-2014-7842",
    "CVE-2014-7970",
    "CVE-2014-7975",
    "CVE-2014-8086",
    "CVE-2014-8160",
    "CVE-2014-8172",
    "CVE-2014-8173",
    "CVE-2014-8369",
    "CVE-2014-8480",
    "CVE-2014-8481",
    "CVE-2014-8559",
    "CVE-2014-8709",
    "CVE-2014-8884",
    "CVE-2014-9090",
    "CVE-2014-9322",
    "CVE-2014-9419",
    "CVE-2014-9420",
    "CVE-2014-9529",
    "CVE-2014-9584",
    "CVE-2014-9585"
  );
  script_bugtraq_id(
    70314,
    70319,
    70376,
    70710,
    70712,
    70747,
    70749,
    70854,
    70965,
    71078,
    71081,
    71097,
    71250,
    71685,
    71717,
    71794,
    71880,
    71883,
    71990,
    72061,
    72994,
    73133
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1483)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in the way the Linux kernel's SCTP
    implementation validated INIT chunks when performing
    Address Configuration Change (ASCONF). A remote
    attacker could use this flaw to crash the system by
    sending a specially crafted SCTP packet to trigger a
    NULL pointer dereference on the system.(CVE-2014-7841)

  - It was found that reporting emulation failures to user
    space could lead to either a local (CVE-2014-7842) or a
    L2-i1/4zL1 (CVE-2010-5313) denial of service. In the case
    of a local denial of service, an attacker must have
    access to the MMIO area or be able to access an I/O
    port. Please note that on certain systems, HPET is
    mapped to userspace as part of vdso (vvar) and thus an
    unprivileged user may generate MMIO transactions (and
    enter the emulator) this way.(CVE-2014-7842)

  - The pivot_root implementation in fs/namespace.c in the
    Linux kernel through 3.17 does not properly interact
    with certain locations of a chroot directory, which
    allows local users to cause a denial of service
    (mount-tree loop) via . (dot) values in both arguments
    to the pivot_root system call.(CVE-2014-7970)

  - The do_umount function in fs/namespace.c in the Linux
    kernel through 3.17 does not require the CAP_SYS_ADMIN
    capability for do_remount_sb calls that change the root
    filesystem to read-only, which allows local users to
    cause a denial of service (loss of writability) by
    making certain unshare system calls, clearing the /
    MNT_LOCKED flag, and making an MNT_FORCE umount system
    call.(CVE-2014-7975)

  - A race condition flaw was found in the Linux kernel's
    ext4 file system implementation that allowed a local,
    unprivileged user to crash the system by simultaneously
    writing to a file and toggling the O_DIRECT flag using
    fcntl(F_SETFL) on that file.(CVE-2014-8086)

  - A flaw was found in the way the Linux kernel's
    netfilter subsystem handled generic protocol tracking.
    As demonstrated in the Stream Control Transmission
    Protocol (SCTP) case, a remote attacker could use this
    flaw to bypass intended iptables rule restrictions when
    the associated connection tracking module was not
    loaded on the system.(CVE-2014-8160)

  - It was found that due to excessive files_lock locking,
    a soft lockup could be triggered in the Linux kernel
    when performing asynchronous I/O operations. A local,
    unprivileged user could use this flaw to crash the
    system.(CVE-2014-8172)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's madvise MADV_WILLNEED functionality
    handled page table locking. A local, unprivileged user
    could use this flaw to crash the system.(CVE-2014-8173)

  - It was found that the fix for CVE-2014-3601 was
    incomplete: the Linux kernel's kvm_iommu_map_pages()
    function still handled IOMMU mapping failures
    incorrectly. A privileged user in a guest with an
    assigned host device could use this flaw to crash the
    host.(CVE-2014-8369)

  - The instruction decoder in arch/x86/kvm/emulate.c in
    the KVM subsystem in the Linux kernel before 3.18-rc2
    lacks intended decoder-table flags for certain
    RIP-relative instructions, which allows guest OS users
    to cause a denial of service (NULL pointer dereference
    and host OS crash) via a crafted
    application.(CVE-2014-8480)

  - The instruction decoder in arch/x86/kvm/emulate.c in
    the KVM subsystem in the Linux kernel before 3.18-rc2
    does not properly handle invalid instructions, which
    allows guest OS users to cause a denial of service
    (NULL pointer dereference and host OS crash) via a
    crafted application that triggers (1) an improperly
    fetched instruction or (2) an instruction that occupies
    too many bytes. NOTE: this vulnerability exists because
    of an incomplete fix for CVE-2014-8480.(CVE-2014-8481)

  - A flaw was found in the way the Linux kernel's VFS
    subsystem handled file system locks. A local,
    unprivileged user could use this flaw to trigger a
    deadlock in the kernel, causing a denial of service on
    the system.(CVE-2014-8559)

  - An information leak flaw was found in the Linux
    kernel's IEEE 802.11 wireless networking
    implementation. When software encryption was used, a
    remote attacker could use this flaw to leak up to 8
    bytes of plaintext.(CVE-2014-8709)

  - A stack-based buffer overflow flaw was found in the
    TechnoTrend/Hauppauge DEC USB device driver. A local
    user with write access to the corresponding device
    could use this flaw to crash the kernel or,
    potentially, elevate their privileges on the
    system.(CVE-2014-8884)

  - The do_double_fault function in arch/x86/kernel/traps.c
    in the Linux kernel through 3.17.4 does not properly
    handle faults associated with the Stack Segment (SS)
    segment register, which allows local users to cause a
    denial of service (panic) via a modify_ldt system call,
    as demonstrated by sigreturn_32 in the
    linux-clock-tests test suite.(CVE-2014-9090)

  - A flaw was found in the way the Linux kernel handled GS
    segment register base switching when recovering from a
    #SS (stack segment) fault on an erroneous return to
    user space. A local, unprivileged user could use this
    flaw to escalate their privileges on the
    system.(CVE-2014-9322)

  - An information leak flaw was found in the way the Linux
    kernel changed certain segment registers and
    thread-local storage (TLS) during a context switch. A
    local, unprivileged user could use this flaw to leak
    the user space TLS base address of an arbitrary
    process.(CVE-2014-9419)

  - It was found that the Linux kernel's ISO file system
    implementation did not correctly limit the traversal of
    Rock Ridge extension Continuation Entries (CE). An
    attacker with physical access to the system could use
    this flaw to trigger an infinite loop in the kernel,
    resulting in a denial of service.(CVE-2014-9420)

  - A race condition flaw was found in the way the Linux
    kernel keys management subsystem performed key garbage
    collection. A local attacker could attempt accessing a
    key while it was being garbage collected, which would
    cause the system to crash.(CVE-2014-9529)

  - An information leak flaw was found in the way the Linux
    kernel's ISO9660 file system implementation accessed
    data on an ISO9660 image with RockRidge Extension
    Reference (ER) records. An attacker with physical
    access to the system could use this flaw to disclose up
    to 255 bytes of kernel memory.(CVE-2014-9584)

  - An information leak flaw was found in the way the Linux
    kernel's Virtual Dynamic Shared Object (vDSO)
    implementation performed address randomization. A
    local, unprivileged user could use this flaw to leak
    kernel memory addresses to user-space.(CVE-2014-9585)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1483
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a214843a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9322");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
