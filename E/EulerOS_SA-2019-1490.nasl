#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124814);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-6381",
    "CVE-2015-1805",
    "CVE-2016-8645",
    "CVE-2017-18202",
    "CVE-2018-1093"
  );
  script_bugtraq_id(63890, 74951);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : kernel (EulerOS-SA-2019-1490)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The __oom_reap_task_mm function in mm/oom_kill.c in the
    Linux kernel, before 4.14.4, mishandles gather
    operations. This allows attackers to cause a denial of
    service (TLB entry leak or use-after-free) or possibly
    have unspecified other impact by triggering a
    copy_to_user call within a certain time
    window.(CVE-2017-18202i1/4%0

  - Buffer overflow in the qeth_snmp_command function in
    drivers/s390/net/qeth_core_main.c in the Linux kernel
    through 3.12.1 allows local users to cause a denial of
    service or possibly have unspecified other impact via
    an SNMP ioctl call with a length value that is
    incompatible with the command-buffer
    size.(CVE-2013-6381i1/4%0

  - It was discovered that the Linux kernel since 3.6-rc1
    with 'net.ipv4.tcp_fastopen' set to 1 can hit BUG()
    statement in tcp_collapse() function after making a
    number of certain syscalls leading to a possible system
    crash.(CVE-2016-8645i1/4%0

  - It was found that the Linux kernel's implementation of
    vectored pipe read and write functionality did not take
    into account the I/O vectors that were already
    processed when retrying after a failed atomic access
    operation, potentially resulting in memory corruption
    due to an I/O vector array overrun. A local,
    unprivileged user could use this flaw to crash the
    system or, potentially, escalate their privileges on
    the system.(CVE-2015-1805i1/4%0

  - The Linux kernel is vulnerable to an out-of-bounds read
    in ext4/balloc.c:ext4_valid_block_bitmap() function. An
    attacker could trick a legitimate user or a privileged
    attacker could exploit this by mounting a crafted ext4
    image to cause a crash.(CVE-2018-1093i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1490
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6426c857");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1805");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-18202");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
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
