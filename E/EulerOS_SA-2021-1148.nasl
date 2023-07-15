#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145726);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2020-0427",
    "CVE-2020-0465",
    "CVE-2020-27068",
    "CVE-2020-27786",
    "CVE-2020-27815",
    "CVE-2020-27830",
    "CVE-2020-28374",
    "CVE-2020-28941",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2021-1148)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

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

  - In create_pinctrl of core.c, there is a possible out of
    bounds read due to a use after free. This could lead to
    local information disclosure with no additional
    execution privileges needed. User interaction is not
    needed for exploitation.(CVE-2020-0427)

  - mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c in the
    Linux kernel through 5.10.4 might allow remote
    attackers to execute arbitrary code via a long SSID
    value, aka CID-5c455c5ab332.(CVE-2020-36158)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - A locking inconsistency issue was discovered in the tty
    subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may
    allow a read-after-free attack against TIOCGSID, aka
    CID-c8bcd9c5be24.(CVE-2020-29660)

  - An issue was discovered in
    drivers/accessibility/speakup/spk_ttyio.c in the Linux
    kernel through 5.9.9. Local attackers on systems with
    the speakup driver could cause a local denial of
    service attack, aka CID-d41227544427. This occurs
    because of an invalid free when the line discipline is
    used more than once.(CVE-2020-28941)

  - NULL-ptr deref in the spk_ttyio_receive_buf2() function
    in spk_ttyio.c.(CVE-2020-27830)

  - In various methods of hid-multitouch.c, there is a
    possible out of bounds write due to a missing bounds
    check. This could lead to local escalation of privilege
    with no additional execution privileges needed. User
    interaction is not needed for
    exploitation.(CVE-2020-0465)

  - A flaw was found in the Linux kernels implementation of
    MIDI, where an attacker with a local account and the
    permissions to issue an ioctl commands to midi devices,
    could trigger a use-after-free. A write to this
    specific memory while freed and before use could cause
    the flow of execution to change and possibly allow for
    memory corruption or privilege
    escalation.(CVE-2020-27786)

  - In the nl80211_policy policy of nl80211.c, there is a
    possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure
    with System execution privileges needed. User
    interaction is not required for
    exploitation.(CVE-2020-27068)

  - A locking issue was discovered in the tty subsystem of
    the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free
    attack against TIOCSPGRP, aka
    CID-54ffccbf053b.(CVE-2020-29661)

  - Array index out of bounds access when setting extended
    attributes on journaling filesystems.(CVE-2020-27815)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1148
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30ea9acb");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h962.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h962.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
