#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dovecot12-4609.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75818);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-1929");

  script_name(english:"openSUSE Security Update : dovecot12 (dovecot12-4609)");
  script_summary(english:"Check for the dovecot12-4609 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dovecot crash when parsing mail headers that contain NUL characters
(CVE-2011-1929)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694778"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot12 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot12-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-mysql-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-mysql-debuginfo-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-pgsql-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-pgsql-debuginfo-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-sqlite-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-backend-sqlite-debuginfo-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-debuginfo-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-debugsource-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-devel-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-fts-lucene-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-fts-lucene-debuginfo-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-fts-solr-1.2.17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"dovecot12-fts-solr-debuginfo-1.2.17-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot12 / dovecot12-backend-mysql / dovecot12-backend-pgsql / etc");
}
