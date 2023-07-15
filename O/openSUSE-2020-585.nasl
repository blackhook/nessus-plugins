#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-585.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136308);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/04");

  script_name(english:"openSUSE Security Update : resource-agents (openSUSE-2020-585)");
  script_summary(english:"Check for the openSUSE-2020-585 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for resource-agents fixes the following issues :

  - Fixed multiple vulnerabilities related to unsafe
    tempfile usage. (bsc#1146690 bsc#1146691 bsc#1146692
    bsc#1146766 bsc#1146776 bsc#1146784 bsc#1146785
    bsc#1146787)

  - Fixed issues where the ocfmon user was created with a
    default password (bsc#1021689, bsc#1146687).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146787"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected resource-agents packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldirectord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:resource-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:resource-agents-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ldirectord-4.3.0184.6ee15eb2-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"monitoring-plugins-metadata-4.3.0184.6ee15eb2-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"resource-agents-4.3.0184.6ee15eb2-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"resource-agents-debuginfo-4.3.0184.6ee15eb2-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"resource-agents-debugsource-4.3.0184.6ee15eb2-lp151.3.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldirectord / monitoring-plugins-metadata / resource-agents / etc");
}
