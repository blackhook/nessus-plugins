#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117572);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-1000199",
    "CVE-2018-10940",
    "CVE-2018-1130",
    "CVE-2018-8897"
  );

  script_name(english:"EulerOS Virtualization 2.5.1 : kernel (EulerOS-SA-2018-1263)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A statement in the System Programming Guide of the
    Intel 64 and IA-32 Architectures Software Developer's
    Manual (SDM) was mishandled in the development of some
    or all operating-system kernels, resulting in
    unexpected behavior for #DB exceptions that are
    deferred by MOV SS or POP SS, as demonstrated by (for
    example) privilege escalation in Windows, macOS, some
    Xen configurations, or FreeBSD, or a Linux kernel
    crash. The MOV to SS and POP SS instructions inhibit
    interrupts (including NMIs), data breakpoints, and
    single step trap exceptions until the instruction
    boundary following the next instruction (SDM Vol. 3A
    section 6.8.3). (The inhibited data breakpoints are
    those on memory accessed by the MOV to SS or POP to SS
    instruction itself.) Note that debug exceptions are not
    inhibited by the interrupt enable (EFLAGS.IF) system
    flag (SDM Vol. 3A section 2.3). If the instruction
    following the MOV to SS or POP to SS instruction is an
    instruction like SYSCALL, SYSENTER, INT 3, etc. that
    transfers control to the operating system at CPL i1/4oe 3,
    the debug exception is delivered after the transfer to
    CPL i1/4oe 3 is complete. OS kernels may not expect this
    order of events and may therefore experience unexpected
    behavior when it occurs.(CVE-2018-8897)

  - A null pointer dereference in dccp_write_xmit()
    function in net/dccp/output.c in the Linux kernel
    allows a local user to cause a denial of service by a
    number of certain crafted system calls.(CVE-2018-1130)

  - The cdrom_ioctl_media_changed function in
    drivers/cdrom/cdrom.c in the Linux kernel before 4.16.6
    allows local attackers to use a incorrect bounds check
    in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read
    out kernel memory.(CVE-2018-10940)

  - An address corruption flaw was discovered in the Linux
    kernel built with hardware breakpoint
    (CONFIG_HAVE_HW_BREAKPOINT) support. While modifying a
    h/w breakpoint via 'modify_user_hw_breakpoint' routine,
    an unprivileged user/process could use this flaw to
    crash the system kernel resulting in DoS OR to
    potentially escalate privileges on a the
    system.(CVE-2018-1000199)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1263
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5222484");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-514.44.5.10_35",
        "kernel-devel-3.10.0-514.44.5.10_35",
        "kernel-headers-3.10.0-514.44.5.10_35",
        "kernel-tools-3.10.0-514.44.5.10_35",
        "kernel-tools-libs-3.10.0-514.44.5.10_35",
        "kernel-tools-libs-devel-3.10.0-514.44.5.10_35"];

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
