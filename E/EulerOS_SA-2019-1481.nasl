#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124805);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/19");

  script_cve_id(
    "CVE-2014-4171",
    "CVE-2014-4652",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-4667",
    "CVE-2014-4699",
    "CVE-2014-4943",
    "CVE-2014-5045",
    "CVE-2014-5077",
    "CVE-2014-5471",
    "CVE-2014-5472",
    "CVE-2014-6410",
    "CVE-2014-6416",
    "CVE-2014-6417",
    "CVE-2014-6418",
    "CVE-2014-7145",
    "CVE-2014-7283",
    "CVE-2014-7825",
    "CVE-2014-7826"
  );
  script_bugtraq_id(
    68157,
    68162,
    68163,
    68164,
    68170,
    68224,
    68411,
    68683,
    68768,
    68862,
    68881,
    69396,
    69428,
    69799,
    69805,
    69867,
    70261,
    70393,
    70395,
    70971,
    70972
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1481)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A race condition flaw was found in the way the Linux
    kernel's mmap(2), madvise(2), and fallocate(2) system
    calls interacted with each other while operating on
    virtual memory file system files. A local user could
    use this flaw to cause a denial of
    service.(CVE-2014-4171)

  - An information leak flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled access of the user control's
    state. A local, privileged user could use this flaw to
    leak kernel memory to user space.(CVE-2014-4652)

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4653)

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4654)

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4655)

  - An integer overflow flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the
    system.(CVE-2014-4656)

  - An integer underflow flaw was found in the way the
    Linux kernel's Stream Control Transmission Protocol
    (SCTP) implementation processed certain COOKIE_ECHO
    packets. By sending a specially crafted SCTP packet, a
    remote attacker could use this flaw to prevent
    legitimate connections to a particular SCTP server
    socket to be made.(CVE-2014-4667)

  - 'It was found that the Linux kernel's ptrace subsystem
    allowed a traced process' instruction pointer to be set
    to a non-canonical memory address without forcing the
    non-sysret code path when returning to user space. A
    local, unprivileged user could use this flaw to crash
    the system or, potentially, escalate their privileges
    on the system.

  - Note: The CVE-2014-4699 issue only affected systems
    using an Intel CPU.(CVE-2014-4699)'

  - A flaw was found in the way the pppol2tp_setsockopt()
    and pppol2tp_getsockopt() functions in the Linux
    kernel's PPP over L2TP implementation handled requests
    with a non-SOL_PPPOL2TP socket option level. A local,
    unprivileged user could use this flaw to escalate their
    privileges on the system.(CVE-2014-4943)

  - A flaw was found in the way the Linux kernel's VFS
    subsystem handled reference counting when performing
    unmount operations on symbolic links. A local,
    unprivileged user could use this flaw to exhaust all
    available memory on the system or, potentially, trigger
    a use-after-free error, resulting in a system crash or
    privilege escalation.(CVE-2014-5045)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's Stream Control Transmission Protocol
    (SCTP) implementation handled simultaneous connections
    between the same hosts. A remote attacker could use
    this flaw to crash the system.(CVE-2014-5077)

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a
    specially crafted ISO image to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-5471)

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a
    specially crafted ISO image to crash the system or,
    potentially, escalate their privileges on the
    system.(CVE-2014-5472)

  - A stack overflow flaw caused by infinite recursion was
    found in the way the Linux kernel's Universal Disk
    Format (UDF) file system implementation processed
    indirect Information Control Blocks (ICBs). An attacker
    with physical access to the system could use a
    specially crafted UDF image to crash the
    system.(CVE-2014-6410)

  - Buffer overflow in net/ceph/auth_x.c in Ceph, as used
    in the Linux kernel before 3.16.3, allows remote
    attackers to cause a denial of service (memory
    corruption and panic) or possibly have unspecified
    other impact via a long unencrypted auth
    ticket.(CVE-2014-6416)

  - net/ceph/auth_x.c in Ceph, as used in the Linux kernel
    before 3.16.3, does not properly consider the
    possibility of kmalloc failure, which allows remote
    attackers to cause a denial of service (system crash)
    or possibly have unspecified other impact via a long
    unencrypted auth ticket.(CVE-2014-6417)

  - net/ceph/auth_x.c in Ceph, as used in the Linux kernel
    before 3.16.3, does not properly validate auth replies,
    which allows remote attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact via crafted data from the IP address of a
    Ceph Monitor.(CVE-2014-6418)

  - A NULL pointer dereference flaw was found in the way
    the Linux kernel's Common Internet File System (CIFS)
    implementation handled mounting of file system shares.
    A remote attacker could use this flaw to crash a client
    system that would mount a file system share from a
    malicious server.(CVE-2014-7145)

  - A denial of service flaw was found in the way the Linux
    kernel's XFS file system implementation ordered
    directory hashes under certain conditions. A local
    attacker could use this flaw to corrupt the file system
    by creating directories with colliding hash values,
    potentially resulting in a system crash.(CVE-2014-7283)

  - An out-of-bounds memory access flaw, CVE-2014-7825, was
    found in the syscall tracing functionality of the Linux
    kernel's perf subsystem. A local, unprivileged user
    could use this flaw to crash the system. Additionally,
    an out-of-bounds memory access flaw, CVE-2014-7826, was
    found in the syscall tracing functionality of the Linux
    kernel's ftrace subsystem. On a system with ftrace
    syscall tracing enabled, a local, unprivileged user
    could use this flaw to crash the system, or escalate
    their privileges.(CVE-2014-7825)

  - An out-of-bounds memory access flaw, CVE-2014-7825, was
    found in the syscall tracing functionality of the Linux
    kernel's perf subsystem. A local, unprivileged user
    could use this flaw to crash the system. Additionally,
    an out-of-bounds memory access flaw, CVE-2014-7826, was
    found in the syscall tracing functionality of the Linux
    kernel's ftrace subsystem. On a system with ftrace
    syscall tracing enabled, a local, unprivileged user
    could use this flaw to crash the system, or escalate
    their privileges.(CVE-2014-7826)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1481
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8a0561b");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7826");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
