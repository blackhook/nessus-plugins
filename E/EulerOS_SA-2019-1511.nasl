#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124833);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2018-1130",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13405",
    "CVE-2018-14633",
    "CVE-2018-14634",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16658",
    "CVE-2018-18690"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1511)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A null pointer dereference in dccp_write_xmit()
    function in net/dccp/output.c in the Linux kernel
    allows a local user to cause a denial of service by a
    number of certain crafted system calls.(CVE-2018-1130)

  - An issue was discovered in the XFS filesystem in
    fs/xfs/xfs_icache.c in the Linux kernel. There is a
    NULL pointer dereference leading to a system panic in
    lookup_slow() on a NULL inode-i1/4zi_ops pointer when
    doing pathwalks on a corrupted xfs image. This occurs
    because of a lack of proper validation that cached
    inodes are free during an allocation.(CVE-2018-13093)

  - An issue was discovered in the XFS filesystem in
    fs/xfs/libxfs/xfs_attr_leaf.c in the Linux kernel. A
    NULL pointer dereference may occur for a corrupted xfs
    image after xfs_da_shrink_inode() is called with a NULL
    bp. This can lead to a system crash and a denial of
    service.(CVE-2018-13094)

  - A vulnerability was found in the
    fs/inode.c:inode_init_owner() function logic of the
    LInux kernel that allows local users to create files
    with an unintended group ownership and with group
    execution and SGID permission bits set, in a scenario
    where a directory is SGID and belongs to a certain
    group and is writable by a user who is not a member of
    this group. This can lead to excessive permissions
    granted in case when they should not.(CVE-2018-13405)

  - A security flaw was found in the
    chap_server_compute_md5() function in the ISCSI target
    code in the Linux kernel in a way an authentication
    request from an ISCSI initiator is processed. An
    unauthenticated remote attacker can cause a stack
    buffer overflow and smash up to 17 bytes of the stack.
    The attack requires the iSCSI target to be enabled on
    the victim host. Depending on how the target's code was
    built (i.e. depending on a compiler, compile flags and
    hardware architecture) an attack may lead to a system
    crash and thus to a denial of service or possibly to a
    non-authorized access to data exported by an iSCSI
    target. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is highly unlikely.(CVE-2018-14633)

  - An integer overflow flaw was found in the Linux
    kernel's create_elf_tables() function. An unprivileged
    local user with access to SUID (or otherwise
    privileged) binary could use this flaw to escalate
    their privileges on the system.(CVE-2018-14634)

  - A flaw was found in the Linux Kernel in the
    ucma_leave_multicast() function in
    drivers/infiniband/core/ucma.c which allows access to a
    certain data structure after freeing it in
    ucma_process_join(). This allows an attacker to cause a
    use-after-free bug and to induce kernel memory
    corruption, leading to a system crash or other
    unspecified impact. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-14734)

  - It was found that paravirt_patch_call/jump() functions
    in the arch/x86/kernel/paravirt.c in the Linux kernel
    mishandles certain indirect calls, which makes it
    easier for attackers to conduct Spectre-v2 attacks
    against paravirtualized guests.(CVE-2018-15594)

  - An information leak was discovered in the Linux kernel
    in cdrom_ioctl_drive_status() function in
    drivers/cdrom/cdrom.c that could be used by local
    attackers to read kernel memory at certain
    location.(CVE-2018-16658)

  - In the Linux kernel before 4.17, a local attacker able
    to set attributes on an xfs filesystem could make this
    filesystem non-operational until the next mount by
    triggering an unchecked error condition during an xfs
    attribute change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandles ATTR_REPLACE
    operations with conversion of an attr from short to
    long form.(CVE-2018-18690)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dfebfa0");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14734");

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
