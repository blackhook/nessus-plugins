#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122414);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-18208",
    "CVE-2017-18255",
    "CVE-2017-18270",
    "CVE-2017-7889",
    "CVE-2018-10021",
    "CVE-2018-1066",
    "CVE-2018-10940",
    "CVE-2018-1120",
    "CVE-2018-1130",
    "CVE-2018-13053",
    "CVE-2018-13094",
    "CVE-2018-13405",
    "CVE-2018-14734",
    "CVE-2018-7757",
    "CVE-2018-7995"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2019-1062)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Missing check in fs/inode.c:inode_init_owner() does not
    clear SGID bit on non-directories for
    non-members.(CVE-2018-13405)

  - A null pointer dereference in dccp_write_xmit()
    function in net/dccp/output.c in the Linux kernel
    allows a local user to cause a denial of service by a
    number of certain crafted system calls.(CVE-2018-1130)

  - A flaw was found in the Linux kernel, before 4.16.6
    where the cdrom_ioctl_media_changed function in
    drivers/cdrom/cdrom.c allows local attackers to use a
    incorrect bounds check in the CDROM driver
    CDROM_MEDIA_CHANGED ioctl to read out kernel
    memory.(CVE-2018-10940)

  - The madvise_willneed function in the Linux kernel
    allows local users to cause a denial of service
    (infinite loop) by triggering use of MADVISE_WILLNEED
    for a DAX mapping.(CVE-2017-18208)

  - fuse-backed file mmap-ed onto process cmdline arguments
    causes denial of service.(CVE-2018-1120)

  - Memory leak in the sas_smp_get_phy_events function in
    drivers/scsi/libsas/sas_expander.c in the Linux kernel
    allows local users to cause a denial of service (kernel
    memory exhaustion) via multiple read accesses to files
    in the /sys/class/sas_phy directory.(CVE-2018-7757)

  - A vulnerability was found in the Linux kernel's
    kernel/events/core.c:perf_cpu_time_max_percent_handler(
    ) function. Local privileged users could exploit this
    flaw to cause a denial of service due to integer
    overflow or possibly have unspecified other
    impact.(CVE-2017-18255)

  - A flaw was found in the Linux kernel in the way a local
    user could create keyrings for other users via keyctl
    commands. This may allow an attacker to set unwanted
    defaults, a denial of service, or possibly leak keyring
    information between users.(CVE-2017-18270)

  - The mm subsystem in the Linux kernel through 4.10.10
    does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read
    or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access
    restrictions) via an application that opens the
    /dev/mem file, related to arch/x86/mm/init.c and
    drivers/char/mem.c.(CVE-2017-7889)

  - The code in the drivers/scsi/libsas/sas_scsi_host.c
    file in the Linux kernel allow a physically proximate
    attacker to cause a memory leak in the ATA command
    queue and, thus, denial of service by triggering
    certain failure conditions.(CVE-2018-10021)

  - A flaw was found in the Linux kernel's client-side
    implementation of the cifs protocol. This flaw allows
    an attacker controlling the server to kernel panic a
    client which has the CIFS server
    mounted.(CVE-2018-1066)

  - A flaw was found in the alarm_timer_nsleep() function
    in kernel/time/alarmtimer.c in the Linux kernel. The
    ktime_add_safe() function is not used and an integer
    overflow can happen causing an alarm not to fire or
    possibly a denial-of-service if using a large relative
    timeout.(CVE-2018-13053)

  - An issue was discovered in the XFS filesystem in
    fs/xfs/libxfs/xfs_attr_leaf.c in the Linux kernel. A
    NULL pointer dereference may occur for a corrupted xfs
    image after xfs_da_shrink_inode() is called with a NULL
    bp. This can lead to a system crash and a denial of
    service.(CVE-2018-13094)

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

  - A race condition in the store_int_with_restart()
    function in arch/x86/kernel/cpu/mcheck/mce.c in the
    Linux kernel allows local users to cause a denial of
    service (panic) by leveraging root access to write to
    the check_interval file in a
    /sys/devices/system/machinecheck/machinecheck (cpu
    number) directory.(CVE-2018-7995)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b15d986");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.62.59.83.h128",
        "kernel-debug-3.10.0-327.62.59.83.h128",
        "kernel-debug-devel-3.10.0-327.62.59.83.h128",
        "kernel-debuginfo-3.10.0-327.62.59.83.h128",
        "kernel-debuginfo-common-x86_64-3.10.0-327.62.59.83.h128",
        "kernel-devel-3.10.0-327.62.59.83.h128",
        "kernel-headers-3.10.0-327.62.59.83.h128",
        "kernel-tools-3.10.0-327.62.59.83.h128",
        "kernel-tools-libs-3.10.0-327.62.59.83.h128",
        "perf-3.10.0-327.62.59.83.h128",
        "python-perf-3.10.0-327.62.59.83.h128"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
