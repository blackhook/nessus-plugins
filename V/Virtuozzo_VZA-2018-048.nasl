#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111151);
  script_version("1.49");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id(
    "CVE-2018-10872",
    "CVE-2018-1120",
    "CVE-2018-3639",
    "CVE-2018-3665"
  );
  script_xref(name:"IAVA", value:"2018-A-0174");

  script_name(english:"Virtuozzo 6 : parallels-server-bm-release / vzkernel / etc (VZA-2018-048)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the parallels-server-bm-release /
vzkernel / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - [x86 AMD] An industry-wide issue was found in the way
    many modern microprocessor designs have implemented
    speculative execution of Load & Store instructions (a
    commonly used performance optimization). It relies on
    the presence of a precisely-defined instruction
    sequence in the privileged code as well as the fact
    that memory read from address to which a recent memory
    write has occurred may see an older value and
    subsequently cause an update into the microprocessor's
    data cache even for speculatively executed instructions
    that never actually commit (retire). As a result, an
    unprivileged attacker could use this flaw to read
    privileged memory by conducting targeted cache
    side-channel attacks.

  - By mmap()ing a FUSE-backed file onto a process's memory
    containing command line arguments (or environment
    strings), an attacker can cause utilities from psutils
    or procps (such as ps, w) or any other program which
    makes a read() call to the /proc/<pid>/cmdline (or
    /proc/<pid>/environ) files to block indefinitely
    (denial of service) or for some controlled time (as a
    synchronization primitive for other attacks).

  - A Floating Point Unit (FPU) state information leakage
    flaw was found in the way the Linux kernel saved and
    restored the FPU state during task switch. Linux
    kernels that follow the 'Lazy FPU Restore' scheme are
    vulnerable to the FPU state information leakage issue.
    An unprivileged local attacker could use this flaw to
    read FPU state bits by conducting targeted cache
    side-channel attacks, similar to the Meltdown
    vulnerability disclosed earlier this year.

  - A flaw was found in the way the Linux kernel handled
    exceptions delivered after a stack switch operation via
    Mov SS or Pop SS instructions. During the stack switch
    operation, processor does not deliver interrupts and
    exceptions, they are delivered once the first
    instruction after the stack switch is executed. An
    unprivileged system user could use this flaw to crash
    the system kernel resulting in DoS. This CVE-2018-10872
    was assigned due to regression of CVE-2018-8897.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2948376");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2164");
  script_set_attribute(attribute:"solution", value:
"Update the affected parallels-server-bm-release / vzkernel / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:parallels-server-bm-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzmodules-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["parallels-server-bm-release-6.0.12-3710",
        "vzkernel-2.6.32-042stab132.1",
        "vzkernel-devel-2.6.32-042stab132.1",
        "vzkernel-firmware-2.6.32-042stab132.1",
        "vzmodules-2.6.32-042stab132.1",
        "vzmodules-devel-2.6.32-042stab132.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "parallels-server-bm-release / vzkernel / etc");
}
