#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110860);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-18255",
    "CVE-2018-1000199",
    "CVE-2018-10021",
    "CVE-2018-10087",
    "CVE-2018-3639",
    "CVE-2018-8781"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2018-1196)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A vulnerability was found in the Linux kernel's
    kernel/events/core.c:perf_cpu_time_max_percent_handler(
    ) function. Local privileged users could exploit this
    flaw to cause a denial of service due to integer
    overflow or possibly have unspecified other
    impact.(CVE-2017-18255)

  - The code in the drivers/scsi/libsas/sas_scsi_host.c
    file in the Linux kernel allow a physically proximate
    attacker to cause a memory leak in the ATA command
    queue and, thus, denial of service by triggering
    certain failure conditions.(CVE-2018-10021)

  - The kernel_wait4 function in kernel/exit.c in the Linux
    kernel, when an unspecified architecture and compiler
    is used, might allow local users to cause a denial of
    service by triggering an attempted use of the -INT_MIN
    value.(CVE-2018-10087)

  - A an integer overflow vulnerability was discovered in
    the Linux kernel, from version 3.4 through 4.15, in the
    drivers/gpu/drm/udl/udl_fb.c:udl_fb_mmap() function. An
    attacker with access to the udldrmfb driver could
    exploit this to obtain full read and write permissions
    on kernel physical pages, resulting in a code execution
    in kernel space.(CVE-2018-8781)

  - An address corruption flaw was discovered in the Linux
    kernel built with hardware breakpoint
    (CONFIG_HAVE_HW_BREAKPOINT) support. While modifying a
    h/w breakpoint via 'modify_user_hw_breakpoint' routine,
    an unprivileged user/process could use this flaw to
    crash the system kernel resulting in DoS OR to
    potentially escalate privileges on a the
    system.(CVE-2018-1000199)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of Load i1/4+ Store instructions (a commonly
    used performance optimization). It relies on the
    presence of a precisely-defined instruction sequence in
    the privileged code as well as the fact that memory
    read from address to which a recent memory write has
    occurred may see an older value and subsequently cause
    an update into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to read privileged memory by
    conducting targeted cache side-channel
    attacks.(CVE-2018-3639)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1196
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afb1a508");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10.h121",
        "kernel-debuginfo-3.10.0-514.44.5.10.h121",
        "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h121",
        "kernel-devel-3.10.0-514.44.5.10.h121",
        "kernel-headers-3.10.0-514.44.5.10.h121",
        "kernel-tools-3.10.0-514.44.5.10.h121",
        "kernel-tools-libs-3.10.0-514.44.5.10.h121",
        "perf-3.10.0-514.44.5.10.h121",
        "python-perf-3.10.0-514.44.5.10.h121"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
