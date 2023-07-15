#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1340.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105230);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15091");

  script_name(english:"openSUSE Security Update : pdns (openSUSE-2017-1340)");
  script_summary(english:"Check for the openSUSE-2017-1340 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pdns fixes the following issues :

Security issue fixed :

  - CVE-2017-15091: An issue has been found in the API
    component of PowerDNS Authoritative, where some
    operations that have an impact on the state of the
    server are still allowed even though the API has been
    configured as read-only. This missing check allows an
    attacker with valid API credentials could flush the
    cache, trigger a zone transfer or send a NOTIFY
    (boo#1069242)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069242"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pdns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-geoip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-godbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-godbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mydns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"pdns-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-ldap-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-ldap-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-lua-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-lua-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-mydns-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-mydns-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-mysql-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-mysql-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-postgresql-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-postgresql-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-sqlite3-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-backend-sqlite3-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-debuginfo-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"pdns-debugsource-3.4.9-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-geoip-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-geoip-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-godbc-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-godbc-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-ldap-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-ldap-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-lua-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-lua-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-mydns-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-mydns-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-mysql-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-mysql-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-postgresql-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-postgresql-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-remote-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-remote-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-sqlite3-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-backend-sqlite3-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-debuginfo-4.0.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"pdns-debugsource-4.0.3-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns / pdns-backend-ldap / pdns-backend-ldap-debuginfo / etc");
}
