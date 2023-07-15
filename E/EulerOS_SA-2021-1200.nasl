#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146181);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-5967",
    "CVE-2020-0305",
    "CVE-2020-0404",
    "CVE-2020-0427",
    "CVE-2020-0431",
    "CVE-2020-0433",
    "CVE-2020-2732",
    "CVE-2020-10773",
    "CVE-2020-12352",
    "CVE-2020-14351",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25656",
    "CVE-2020-25705"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2021-1200)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel. A use-after-free
    was found in the way the console subsystem was using
    ioctls KDGKBSENT and KDSKBSENT. A local user could use
    this flaw to get read memory access out of bounds. The
    highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-25656)

  - The time subsystem in the Linux kernel through 4.9.9,
    when CONFIG_TIMER_STATS is enabled, allows local users
    to discover real PID values (as distinguished from PID
    values inside a PID namespace) by reading the
    /proc/timer_list file, related to the print_timer
    function in kernel/time/timer_list.c and the
    __timer_stats_timer_set_start_info function in
    kernel/time/timer.c.(CVE-2017-5967)

  - A flaw in the way reply ICMP packets are limited in the
    Linux kernel functionality was found that allows to
    quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypassing source
    port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly
    integrity, because software that relies on UDP source
    port randomization are indirectly affected as well.
    Kernel versions before 5.10 may be vulnerable to this
    issue.(CVE-2020-25705)

  - In cdev_get of char_dev.c, there is a possible
    use-after-free due to a race condition. This could lead
    to local escalation of privilege with System execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions:
    Android-10Android ID: A-153467744(CVE-2020-0305)

  - In create_pinctrl of core.c, there is a possible out of
    bounds read due to a use after free. This could lead to
    local information disclosure with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.Product: AndroidVersions:
    Android kernelAndroid ID: A-140550171(CVE-2020-0427)

  - A flaw was discovered in the way that the KVM
    hypervisor handled instruction emulation for an L2
    guest when nested virtualisation is enabled. Under some
    circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be
    inaccessible to the L2 guest.(CVE-2020-2732)

  - In uvc_scan_chain_forward of uvc_driver.c, there is a
    possible linked list corruption due to an unusual root
    cause. This could lead to local escalation of privilege
    in the kernel with no additional execution privileges
    needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-111893654References: Upstream
    kernel(CVE-2020-0404)

  - A stack information leak flaw was found in s390/s390x
    in the Linux kernel's memory manager functionality,
    where it incorrectly writes to the
    /proc/sys/vm/cmm_timeout file. This flaw allows a local
    user to see the kernel data.(CVE-2020-10773)

  - Improper access control in BlueZ may allow an
    unauthenticated user to potentially enable information
    disclosure via adjacent access.(CVE-2020-12352)

  - A flaw was found in the Linux kernel. A use-after-free
    memory flaw was found in the perf subsystem allowing a
    local attacker with permission to monitor perf events
    to corrupt memory and possibly escalate privileges. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-14351)

  - A flaw was found in the HDLC_PPP module of the Linux
    kernel in versions before 5.9-rc7. Memory corruption
    and a read overflow is caused by improper input
    validation in the ppp_cp_parse_cr function which can
    cause the system to crash or cause a denial of service.
    The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25643)

  - A flaw was found in the Linux kernel in versions before
    5.9-rc7. Traffic between two Geneve endpoints may be
    unencrypted when IPsec is configured to encrypt traffic
    for the specific UDP port used by the GENEVE tunnel
    allowing anyone between the two endpoints to read the
    traffic unencrypted. The main threat from this
    vulnerability is to data
    confidentiality.(CVE-2020-25645)

  - In kbd_keycode of keyboard.c, there is a possible out
    of bounds write due to a missing bounds check. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-144161459(CVE-2020-0431)

  - In blk_mq_queue_tag_busy_iter of blk-mq-tag.c, there is
    a possible use after free due to improper locking. This
    could lead to local escalation of privilege with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-151939299(CVE-2020-0433)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1200
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac6252fc");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

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

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h494.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h494.eulerosv2r7"];

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
