#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1493.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119537);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16850");

  script_name(english:"openSUSE Security Update : postgresql10 (openSUSE-2018-1493)");
  script_summary(english:"Check for the openSUSE-2018-1493 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql10 fixes the following issues :

Security issue fixed :

  - CVE-2018-16850: Fixed improper quoting of transition
    table names when pg_dump emits CREATE TRIGGER could have
    caused privilege escalation (bsc#1114837). 

Non-security issues fixed :

  - Update to release 10.6 :

  - https://www.postgresql.org/docs/current/static/release-10-6.html

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114837"
  );
  # https://www.postgresql.org/docs/current/static/release-10-6.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/current/release-10-6.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql10 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libecpg6-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libecpg6-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpq5-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libpq5-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-contrib-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-contrib-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-debugsource-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-devel-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-devel-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plperl-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plperl-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plpython-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-plpython-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-pltcl-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-pltcl-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-server-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-server-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"postgresql10-test-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libecpg6-32bit-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libecpg6-32bit-debuginfo-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpq5-32bit-10.6-lp150.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libpq5-32bit-debuginfo-10.6-lp150.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql10 / postgresql10-contrib / etc");
}
