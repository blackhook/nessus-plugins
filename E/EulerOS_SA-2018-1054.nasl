#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108458);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-18079",
    "CVE-2017-18203",
    "CVE-2017-18208",
    "CVE-2018-1000004",
    "CVE-2018-5750",
    "CVE-2018-6927"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2018-1054)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In the Linux kernel 4.12, 3.10, 2.6 and possibly
    earlier versions a race condition vulnerability exists
    in the sound system, this can lead to a deadlock and
    denial of service condition.(CVE-2018-1000004)

  - drivers/input/serio/i8042.c in the Linux kernel before
    4.12.4 allows attackers to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact because the
    port-i1/4zexists value can change after it is
    validated.(CVE-2017-18079)

  - The acpi_smbus_hc_add function in drivers/acpi/sbshc.c
    in the Linux kernel through 4.14.15 allows local users
    to obtain sensitive address information by reading
    dmesg data from an SBS HC printk call.(CVE-2018-5750)

  - The futex_requeue function in kernel/futex.c in the
    Linux kernel, before 4.14.15, might allow attackers to
    cause a denial of service (integer overflow) or
    possibly have unspecified other impacts by triggering a
    negative wake or requeue value. Due to the nature of
    the flaw, privilege escalation cannot be fully ruled
    out, although we believe it is unlikely.(CVE-2018-6927)

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with
    CAP_SYS_ADMIN capability) can directly perform the
    ioctl operations for dm device creation and removal and
    this would typically be outside the direct control of
    the unprivileged attacker.(CVE-2017-18203)

  - The madvise_willneed function in the Linux kernel
    allows local users to cause a denial of service
    (infinite loop) by triggering use of MADVISE_WILLNEED
    for a DAX mapping.(CVE-2017-18208)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1054
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77855b39");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
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

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.175",
        "kernel-debug-3.10.0-229.49.1.175",
        "kernel-debuginfo-3.10.0-229.49.1.175",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.175",
        "kernel-devel-3.10.0-229.49.1.175",
        "kernel-headers-3.10.0-229.49.1.175",
        "kernel-tools-3.10.0-229.49.1.175",
        "kernel-tools-libs-3.10.0-229.49.1.175",
        "perf-3.10.0-229.49.1.175",
        "python-perf-3.10.0-229.49.1.175"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
