#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146217);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-28374",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2020-36158"
  );

  script_name(english:"EulerOS 2.0 SP9 : kernel (EulerOS-SA-2021-1246)");

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

  - An issue was discovered in Xen through 4.14.x. Some
    OSes (such as Linux, FreeBSD, and NetBSD) are
    processing watch events using a single thread. If the
    events are received faster than the thread is able to
    handle, they will get queued. As the queue is
    unbounded, a guest may be able to trigger an OOM in the
    backend. All systems with a FreeBSD, Linux, or NetBSD
    (any version) dom0 are vulnerable.(CVE-2020-29568)

  - An issue was discovered in the Linux kernel through
    5.10.1, as used with Xen through 4.14.x. The Linux
    kernel PV block backend expects the kernel thread
    handler to reset ring->xenblkd to NULL when stopped.
    However, the handler may not have time to run if the
    frontend quickly toggles between the states connect and
    disconnect. As a consequence, the block backend may
    re-use a pointer after it was freed. A misbehaving
    guest can trigger a dom0 crash by continuously
    connecting / disconnecting a block frontend. Privilege
    escalation and information leaks cannot be ruled out.
    This only affects systems with a Linux
    blkback.(CVE-2020-29569)

  - mwifiex_cmd_802_11_ad_hoc_start in
    drivers/net/wireless/marvell/mwifiex/join.c in the
    Linux kernel through 5.10.4 might allow remote
    attackers to execute arbitrary code via a long SSID
    value, aka CID-5c455c5ab332.(CVE-2020-36158)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1246
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7744bf0c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36158");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
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
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.90-vhulk2011.1.0.h382.eulerosv2r9",
        "kernel-tools-4.19.90-vhulk2011.1.0.h382.eulerosv2r9",
        "kernel-tools-libs-4.19.90-vhulk2011.1.0.h382.eulerosv2r9",
        "python3-perf-4.19.90-vhulk2011.1.0.h382.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
