#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-720.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136961);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2020-10957", "CVE-2020-10958", "CVE-2020-10967");

  script_name(english:"openSUSE Security Update : dovecot23 (openSUSE-2020-720)");
  script_summary(english:"Check for the openSUSE-2020-720 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for dovecot23 to 2.3.10 fixes the following issues :

Security issues fixed :

  - CVE-2020-10957: Fixed a crash caused by malformed NOOP
    commands (bsc#1171457).

  - CVE-2020-10958: Fixed a use-after-free when receiving
    too many newlines (bsc#1171458).

  - CVE-2020-10967: Fixed a crash in the lmtp and submission
    components caused by mails with empty quoted localparts
    (bsc#1171456).

Non-security issues fixed :

  - The update to 2.3.10 fixes several bugs. Please refer to
    https://dovecot.org/doc/NEWS for a complete list of
    changes.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://dovecot.org/doc/NEWS"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected dovecot23 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10967");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot23-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-mysql-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-mysql-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-pgsql-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-pgsql-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-sqlite-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-backend-sqlite-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-debugsource-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-devel-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-lucene-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-lucene-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-solr-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-solr-debuginfo-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-squat-2.3.10-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"dovecot23-fts-squat-debuginfo-2.3.10-lp151.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot23 / dovecot23-backend-mysql / etc");
}
