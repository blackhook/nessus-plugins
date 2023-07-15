#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2937-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130899);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-17041", "CVE-2019-17042");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : rsyslog (SUSE-SU-2019:2937-1)");
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

Other issue addressed: Fixed an issue where rsyslog was SEGFAULT due
to a mutex double-unlock (bsc#1141063).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141063"
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
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192937-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b667a1c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Server-Applications-15-SP1-2019-2937=1

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-2937=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2937=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2937=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2937=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2937=1"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-dbi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-elasticsearch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gssapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gtls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-gtls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mmnormalize-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omamqp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omamqp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omhttpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omhttpfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omtcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-omtcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-relp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-udpspoof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rsyslog-module-udpspoof-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-debugsource-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-diag-tools-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-diag-tools-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-doc-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-dbi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-dbi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-elasticsearch-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-elasticsearch-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gcrypt-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gcrypt-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gssapi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gssapi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gtls-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-gtls-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-mmnormalize-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-mmnormalize-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-mysql-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-mysql-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omamqp1-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omamqp1-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omhttpfs-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omhttpfs-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omtcl-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-omtcl-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-pgsql-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-pgsql-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-relp-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-relp-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-snmp-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-snmp-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-udpspoof-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rsyslog-module-udpspoof-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-debugsource-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-diag-tools-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-diag-tools-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-doc-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-dbi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-dbi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-elasticsearch-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-elasticsearch-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gcrypt-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gcrypt-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gssapi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gssapi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gtls-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-gtls-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-mmnormalize-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-mmnormalize-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-mysql-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-mysql-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omamqp1-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omamqp1-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omhttpfs-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omhttpfs-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omtcl-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-omtcl-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-pgsql-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-pgsql-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-relp-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-relp-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-snmp-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-snmp-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-udpspoof-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"rsyslog-module-udpspoof-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-debugsource-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-diag-tools-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-diag-tools-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-doc-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-dbi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-dbi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-elasticsearch-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-elasticsearch-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-gcrypt-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-gcrypt-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-mmnormalize-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-mmnormalize-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omamqp1-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omamqp1-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omhttpfs-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omhttpfs-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omtcl-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rsyslog-module-omtcl-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-debugsource-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-diag-tools-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-diag-tools-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-doc-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-dbi-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-dbi-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-elasticsearch-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-elasticsearch-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-gcrypt-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-gcrypt-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-gtls-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-gtls-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-mmnormalize-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-mmnormalize-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omamqp1-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omamqp1-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omhttpfs-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omhttpfs-debuginfo-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omtcl-8.33.1-3.22.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"rsyslog-module-omtcl-debuginfo-8.33.1-3.22.4")) flag++;


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
