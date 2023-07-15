#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0027-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(144763);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-12100", "CVE-2020-24386", "CVE-2020-25275");

  script_name(english:"SUSE SLES15 Security Update : dovecot23 (SUSE-SU-2021:0027-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for dovecot23 fixes the following issues :

Security issues fixed :

CVE-2020-12100: Fixed a resource exhaustion caused by deeply nested
MIME parts (bsc#1174920).

CVE-2020-24386: Fixed an issue with IMAP hibernation that allowed
users to access other users' emails (bsc#1180405).

CVE-2020-25275: Fixed a crash when the 10000th MIME part was
message/rfc822 (bsc#1180406).

Non-security issues fixed :

Pigeonhole was updated to version 0.5.11.

Dovecot was updated to version 2.3.11.3.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12100/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-24386/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25275/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210027-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04c03a16"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP1-2021-27=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24386");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dovecot23-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-mysql-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-mysql-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-pgsql-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-pgsql-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-sqlite-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-backend-sqlite-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-debugsource-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-devel-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-lucene-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-lucene-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-solr-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-solr-debuginfo-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-squat-2.3.11.3-21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"dovecot23-fts-squat-debuginfo-2.3.11.3-21.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot23");
}
