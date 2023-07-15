#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3333-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120141);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/10 13:51:49");

  script_cve_id("CVE-2018-18065");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : net-snmp (SUSE-SU-2018:3333-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for net-snmp fixes the following issues :

Security issues fixed :

CVE-2018-18065: _set_key in agent/helpers/table_container.c had a NULL
Pointer Exception bug that can be used by an authenticated attacker to
remotely cause the instance to crash via a crafted UDP packet,
resulting in Denial of Service. (bsc#1111122)

Non-security issues fixed: swintst_rpm: Protect against unspecified
Group name (bsc#1102775)

Add tsm and tlstm MIBs and the USM security module. (bsc#1081164)

Fix agentx freezing on timeout (bsc#1027353)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18065/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183333-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b06a53cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2396=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsnmp30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-SNMP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-SNMP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:snmp-mibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/23");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"libsnmp30-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsnmp30-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"net-snmp-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"net-snmp-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"net-snmp-debugsource-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"net-snmp-devel-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-SNMP-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-SNMP-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"snmp-mibs-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsnmp30-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsnmp30-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"net-snmp-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"net-snmp-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"net-snmp-debugsource-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"net-snmp-devel-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-SNMP-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-SNMP-debuginfo-5.7.3-7.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"snmp-mibs-5.7.3-7.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
