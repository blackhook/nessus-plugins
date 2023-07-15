#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124804);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2014-3153",
    "CVE-2014-3181",
    "CVE-2014-3182",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3534",
    "CVE-2014-3601",
    "CVE-2014-3610",
    "CVE-2014-3611",
    "CVE-2014-3631",
    "CVE-2014-3645",
    "CVE-2014-3646",
    "CVE-2014-3647",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-3688",
    "CVE-2014-3690",
    "CVE-2014-3917",
    "CVE-2014-3940",
    "CVE-2014-4014",
    "CVE-2014-4027"
  );
  script_bugtraq_id(
    67699,
    67786,
    67906,
    67985,
    67988,
    68159,
    68940,
    69489,
    69768,
    69770,
    69779,
    69781,
    70095,
    70691,
    70742,
    70743,
    70745,
    70746,
    70748,
    70766,
    70768,
    70883
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1480)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in the way the Linux kernel's futex
    subsystem handled the requeuing of certain Priority
    Inheritance (PI) futexes. A local, unprivileged user
    could use this flaw to escalate their privileges on the
    system.(CVE-2014-3153)

  - An out-of-bounds write flaw was found in the way the
    Apple Magic Mouse/Trackpad multi-touch driver handled
    Human Interface Device (HID) reports with an invalid
    size. An attacker with physical access to the system
    could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-3181)

  - An out-of-bounds read flaw was found in the way the
    Logitech Unifying receiver driver handled HID reports
    with an invalid device_index value. An attacker with
    physical access to the system could use this flaw to
    crash the system or, potentially, escalate their
    privileges on the system.(CVE-2014-3182)

  - Multiple out-of-bounds write flaws were found in the
    way the Cherry Cymotion keyboard driver, KYE/Genius
    device drivers, Logitech device drivers, Monterey
    Genius KB29E keyboard driver, Petalynx Maxter remote
    control driver, and Sunplus wireless desktop driver
    handled HID reports with an invalid report descriptor
    size. An attacker with physical access to the system
    could use either of these flaws to write data past an
    allocated memory buffer.(CVE-2014-3184)

  - A memory corruption flaw was found in the way the USB
    ConnectTech WhiteHEAT serial driver processed
    completion commands sent via USB Request Blocks
    buffers. An attacker with physical access to the system
    could use this flaw to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-3185)

  - It was found that Linux kernel's ptrace subsystem did
    not properly sanitize the address-space-control bits
    when the program-status word (PSW) was being set. On
    IBM S/390 systems, a local, unprivileged user could use
    this flaw to set address-space-control bits to the
    kernel space, and thus gain read and write access to
    kernel memory.(CVE-2014-3534)

  - A flaw was found in the way the Linux kernel's
    kvm_iommu_map_pages() function handled IOMMU mapping
    failures. A privileged user in a guest with an assigned
    host device could use this flaw to crash the
    host.(CVE-2014-3601)

  - It was found that KVM's Write to Model Specific
    Register (WRMSR) instruction emulation would write
    non-canonical values passed in by the guest to certain
    MSRs in the host's context. A privileged guest user
    could use this flaw to crash the host.(CVE-2014-3610)

  - A race condition flaw was found in the way the Linux
    kernel's KVM subsystem handled PIT (Programmable
    Interval Timer) emulation. A guest user who has access
    to the PIT I/O ports could use this flaw to crash the
    host.(CVE-2014-3611)

  - A flaw was found in the way the Linux kernel's keys
    subsystem handled the termination condition in the
    associative array garbage collection functionality. A
    local, unprivileged user could use this flaw to crash
    the system.(CVE-2014-3631)

  - It was found that the Linux kernel's KVM subsystem did
    not handle the VM exits gracefully for the invept
    (Invalidate Translations Derived from EPT)
    instructions. On hosts with an Intel processor and
    invept VM exit support, an unprivileged guest user
    could use these instructions to crash the
    guest.(CVE-2014-3645)

  - It was found that the Linux kernel's KVM subsystem did
    not handle the VM exits gracefully for the invvpid
    (Invalidate Translations Based on VPID) instructions.
    On hosts with an Intel processor and invppid VM exit
    support, an unprivileged guest user could use these
    instructions to crash the guest.(CVE-2014-3646)

  - A flaw was found in the way the Linux kernel's KVM
    subsystem handled non-canonical addresses when
    emulating instructions that change the RIP (for
    example, branches or calls). A guest user with access
    to an I/O or MMIO region could use this flaw to crash
    the guest.(CVE-2014-3647)

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled malformed Address Configuration Change Chunks
    (ASCONF). A remote attacker could use either of these
    flaws to crash the system.(CVE-2014-3673)

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled duplicate Address Configuration Change Chunks
    (ASCONF). A remote attacker could use either of these
    flaws to crash the system.(CVE-2014-3687)

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled the association's output queue. A remote
    attacker could send specially crafted packets that
    would cause the system to use an excessive amount of
    memory, leading to a denial of service.(CVE-2014-3688)

  - It was found that the Linux kernel's KVM implementation
    did not ensure that the host CR4 control register value
    remained unchanged across VM entries on the same
    virtual CPU. A local, unprivileged user could use this
    flaw to cause a denial of service on the
    system.(CVE-2014-3690)

  - An out-of-bounds memory access flaw was found in the
    Linux kernel's system call auditing implementation. On
    a system with existing audit rules defined, a local,
    unprivileged user could use this flaw to leak kernel
    memory to user space or, potentially, crash the
    system.(CVE-2014-3917)

  - A flaw was found in the way Linux kernel's Transparent
    Huge Pages (THP) implementation handled non-huge page
    migration. A local, unprivileged user could use this
    flaw to crash the kernel by migrating transparent
    hugepages.(CVE-2014-3940)

  - The capabilities implementation in the Linux kernel
    before 3.14.8 does not properly consider that
    namespaces are inapplicable to inodes, which allows
    local users to bypass intended chmod restrictions by
    first creating a user namespace, as demonstrated by
    setting the setgid bit on a file with group ownership
    of root.(CVE-2014-4014)

  - An information leak flaw was found in the RAM Disks
    Memory Copy (rd_mcp) backend driver of the iSCSI Target
    subsystem of the Linux kernel. A privileged user could
    use this flaw to leak the contents of kernel memory to
    an iSCSI initiator remote client.(CVE-2014-4027)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1480
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fae85682");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3687");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Towelroot Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

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

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
