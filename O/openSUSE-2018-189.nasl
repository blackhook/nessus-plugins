#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-189.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106921);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15132");

  script_name(english:"openSUSE Security Update : dovecot22 (openSUSE-2018-189)");
  script_summary(english:"Check for the openSUSE-2018-189 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dovecot22 fixes one issue.

This security issue was fixed :

  - CVE-2017-15132: An abort of SASL authentication resulted
    in a memory leak in dovecot's auth client used by login
    processes. The leak has impact in high performance
    configuration where same login processes are reused and
    can cause the process to crash due to memory exhaustion
    (bsc#1075608).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075608"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot22 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-mysql-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-mysql-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-pgsql-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-pgsql-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-sqlite-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-sqlite-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-debugsource-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-devel-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-lucene-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-lucene-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-solr-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-solr-debuginfo-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-squat-2.2.31-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-squat-debuginfo-2.2.31-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot22 / dovecot22-backend-mysql / etc");
}
