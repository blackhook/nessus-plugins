#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2685.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(132068);
  script_version("1.1");
  script_cvs_date("Date: 2019/12/16");

  script_name(english:"openSUSE Security Update : postgresql (openSUSE-2019-2685)");
  script_summary(english:"Check for the openSUSE-2019-2685 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql fixes the following issues :

  - Changed permissions, so that the directory can only be
    used by users in the postgres group (bsc#1123886).

  - Moved bash profile out of /var/lib to allow
    transactional updates (bsc#1100397).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123886"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"postgresql-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-contrib-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-devel-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-plperl-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-plpython-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-pltcl-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-server-10-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql-test-10-lp151.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-devel / etc");
}
