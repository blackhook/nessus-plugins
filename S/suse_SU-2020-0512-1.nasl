#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0512-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134160);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");

  script_name(english:"SUSE SLES12 Security Update : rsyslog (SUSE-SU-2020:0512-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for rsyslog fixes the following issues :

Security issues fixed :

CVE-2019-17041: Fixed a heap overflow in the parser for AIX log
messages (bsc#1153451).

CVE-2019-17042: Fixed a heap overflow in the parser for Cisco log
messages (bsc#1153459).

Non-security issues fixed: Handle multiline messages correctly when
using the imfile module. (bsc#1015203)

Fix a race condition in the shutdown sequence in wtp that was causing
rsyslog not to shutdown properly. (bsc#1022804)

Fixed a rsyslogd SIGABORT crash if a path does not exists
(bsc#1087920).

Fixed an issue where configuration templates where not consistently
flushed (bsc#1084682).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17041/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17042/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200512-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cf52712"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-512=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-512=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-512=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-512=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-diag-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-diag-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gtls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-relp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-udpspoof-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-debugsource-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-diag-tools-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-diag-tools-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-doc-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-gssapi-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-gssapi-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-gtls-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-gtls-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-mysql-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-mysql-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-pgsql-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-pgsql-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-relp-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-relp-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-snmp-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-snmp-debuginfo-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-udpspoof-8.4.0-18.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"rsyslog-module-udpspoof-debuginfo-8.4.0-18.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog");
}
