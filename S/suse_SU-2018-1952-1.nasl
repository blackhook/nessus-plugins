#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1952-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120048);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : Initial update for kernel-azure (SUSE-SU-2018:1952-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update is the initial delivery of the Azure flavor of the Linux
Kernel, which contains enhancements and optimizations for running the
SUSE Linux Enterprise kernel in the Azure cloud.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094420"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181952-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c518faf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2018-1324=1

SUSE Linux Enterprise Module for Public Cloud 15:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-15-2018-1324=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2018-1324=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2018-1324=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdpdk-17_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdpdk-17_11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-debuginfo-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-debugsource-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-devel-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-devel-debuginfo-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-kmp-default-17.11.2_k4.12.14_23-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-kmp-default-debuginfo-17.11.2_k4.12.14_23-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-tools-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"dpdk-tools-debuginfo-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdpdk-17_11-0-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdpdk-17_11-0-debuginfo-17.11.2-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-2.10.0-5.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-debugsource-2.10.0-5.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.10.0_k4.12.14_23-5.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.10.0_k4.12.14_23-5.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-debuginfo-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-debugsource-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-devel-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-kmp-default-7.2.1_k4.12.14_23-3.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"crash-kmp-default-debuginfo-7.2.1_k4.12.14_23-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-2.10.0-5.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-debugsource-2.10.0-5.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.10.0_k4.12.14_23-5.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.10.0_k4.12.14_23-5.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-debuginfo-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-debugsource-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-devel-7.2.1-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-kmp-default-7.2.1_k4.12.14_23-3.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"crash-kmp-default-debuginfo-7.2.1_k4.12.14_23-3.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Initial update for kernel-azure");
}
