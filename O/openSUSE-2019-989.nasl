#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-989.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10851", "CVE-2018-14626");

  script_name(english:"openSUSE Security Update : pdns (openSUSE-2019-989)");
  script_summary(english:"Check for the openSUSE-2019-989 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pdns fixes the following issues :

Security issues fixed :

  - CVE-2018-10851: Fixed denial of service via crafted zone
    record or crafted answer (bsc#1114157).

  - CVE-2018-14626: Fixed packet cache pollution via crafted
    query (bsc#1114169)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114169"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pdns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"pdns-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-geoip-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-geoip-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-godbc-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-godbc-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-ldap-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-ldap-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-lua-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-lua-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mydns-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mydns-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mysql-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-mysql-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-postgresql-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-postgresql-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-remote-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-remote-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-sqlite3-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-backend-sqlite3-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-debuginfo-4.1.2-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"pdns-debugsource-4.1.2-lp150.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns / pdns-backend-geoip / pdns-backend-geoip-debuginfo / etc");
}
