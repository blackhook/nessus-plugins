#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147588);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2020-0423",
    "CVE-2020-0427",
    "CVE-2020-0444",
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-4788",
    "CVE-2020-8694",
    "CVE-2020-14381",
    "CVE-2020-25668",
    "CVE-2020-25705",
    "CVE-2020-27068",
    "CVE-2020-27786",
    "CVE-2020-27815",
    "CVE-2020-27830",
    "CVE-2020-28374",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158",
    "CVE-2021-0342",
    "CVE-2021-3347",
    "CVE-2021-3348"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : kernel (EulerOS-SA-2021-1386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A locking inconsistency issue was discovered in the tty
    subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    allow a read-after-free attack against TIOCGSID, aka
    CID-c8bcd9c5be24.(CVE-2020-29660)

  - A locking vulnerability was found in the tty subsystem
    of the Linux kernel in drivers/tty/tty_jobctrl.c. This
    flaw allows a local attacker to possibly corrupt memory
    or escalate privileges. The highest threat from this
    vulnerability is to confidentiality, integrity, as well
    as system availability.(CVE-2020-29661)

  - The Linux kernel is the kernel used by the open source
    operating system Linux released by the Linux
    Foundation. The Linux kernel con_font_op() has a code
    problem vulnerability, which can force the use of freed
    memory, resulting in denial of service or execution of
    custom code.(CVE-2020-25668 CVE-2020-4788
    CVE-2020-27830)

  - A flaw was found in the Linux kernel's implementation
    of MIDI, where an attacker with a local account and the
    permissions to issue ioctl commands to midi devices
    could trigger a use-after-free issue. A write to this
    specific memory while freed and before use causes the
    flow of execution to change and possibly allow for
    memory corruption or privilege escalation. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system (CVE-2020-27786)

  - In various methods of hid-multitouch.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-162844689References: Upstream kernel(CVE-2020-0465)

  - In the nl80211_policy policy of nl80211.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with System execution privileges needed. User
    interaction is not required for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-119770583(CVE-2020-27068)

  - In do_epoll_ctl and ep_loop_check_proc of eventpoll.c,
    there is a possible use after free due to a logic
    error. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-147802478References: Upstream kernel(CVE-2020-0466)

  - In audit_free_lsm_field of auditfilter.c, there is a
    possible bad kfree due to a logic error in
    audit_data_to_entry. This could lead to local
    escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for
    exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-150693166References: Upstream
    kernel(CVE-2020-0444)

  - No description is available for this
    CVE.(CVE-2020-27815)

  - A flaw was found in the Linux kernel. The marvell wifi
    driver could allow a local attacker to execute
    arbitrary code via a long SSID value in
    mwifiex_cmd_802_11_ad_hoc_start function. The highest
    threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-36158)

  - In create_pinctrl of core.c, there is a possible out of
    bounds read due to a use after free. This could lead to
    local information disclosure with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.Product: AndroidVersions:
    Android kernelAndroid ID: A-140550171(CVE-2020-0427)

  - In binder_release_work of binder.c, there is a possible
    use-after-free due to improper locking. This could lead
    to local escalation of privilege in the kernel with no
    additional execution privileges needed. User
    interaction is not needed for exploitation.Product:
    AndroidVersions: Android kernelAndroid ID:
    A-161151868References: N/A(CVE-2020-0423)

  - In drivers/target/target_core_xcopy.c in the Linux
    kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote
    attackers to read or write files via directory
    traversal in an XCOPY request, aka CID-2896c93811e3.
    For example, an attack can occur over a network if the
    attacker has access to one iSCSI LUN. The attacker
    gains control over file access because I/O operations
    are proxied via an attacker-selected
    backstore.(CVE-2020-28374)

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

  - Insufficient access control in the Linux kernel driver
    for some Intel(R) Processors may allow an authenticated
    user to potentially enable information disclosure via
    local access.(CVE-2020-8694)

  - A flaw was found in the Linux kernel's futex
    implementation. This flaw allows a local attacker to
    corrupt system memory or escalate their privileges when
    creating a futex on a filesystem that is about to be
    unmounted. The highest threat from this vulnerability
    is to confidentiality, integrity, as well as system
    availability.(CVE-2020-14381)

  - In tun_get_user of tun.c, there is possible memory
    corruption due to a use after free. This could lead to
    local escalation of privilege with System execution
    privileges required. User interaction is not required
    for exploitation. Product: Android Versions: Android
    kernel Android ID: A-146554327.(CVE-2021-0342)

  - A flaw was found in the Linux kernel. A use-after-free
    memory flaw in the Fast Userspace Mutexes functionality
    allowing a local user to crash the system or escalate
    their privileges on the system. The highest threat from
    this vulnerability is to data confidentiality and
    integrity as well as system
    availability.(CVE-2021-3347)

  - A use after free flaw in the Linux kernel network block
    device (NBD) subsystem was found in the way user calls
    an ioctl NBD_SET_SOCK at a certain point during device
    setup.(CVE-2021-3348)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1386
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?499dd13a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1907.1.0.h972",
        "kernel-devel-4.19.36-vhulk1907.1.0.h972",
        "kernel-headers-4.19.36-vhulk1907.1.0.h972",
        "kernel-tools-4.19.36-vhulk1907.1.0.h972",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h972",
        "kernel-tools-libs-devel-4.19.36-vhulk1907.1.0.h972"];

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
