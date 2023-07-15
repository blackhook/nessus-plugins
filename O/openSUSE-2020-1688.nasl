#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1688.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141533);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_name(english:"openSUSE Security Update : crmsh (openSUSE-2020-1688)");
  script_summary(english:"Check for the openSUSE-2020-1688 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for crmsh fixes the following issues :

  - Fixed start_delay with start-delay(bsc#1176569)

  - fix on_fail should be on-fail(bsc#1176569)

  - config: Try to handle
    configparser.MissingSectionHeaderError while reading
    config file

  - ui_configure: Obscure sensitive data by
    default(bsc#1163581)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176569"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected crmsh packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crmsh-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"crmsh-4.1.0+git.1602227275.3d680577-lp151.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crmsh-scripts-4.1.0+git.1602227275.3d680577-lp151.2.33.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crmsh-test-4.1.0+git.1602227275.3d680577-lp151.2.33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "crmsh / crmsh-scripts / crmsh-test");
}
