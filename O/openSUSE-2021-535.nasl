#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-535.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148435);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_name(english:"openSUSE Security Update : bcc (openSUSE-2021-535)");
  script_summary(english:"Check for the openSUSE-2021-535 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for bcc fixes the following issues :

  - Enabled PIE for bcc-lua if lua support is enabled
    (bsc#1183399)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183399"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bcc packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bcc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbcc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbcc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-bcc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"bcc-debuginfo-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-debugsource-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-devel-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-examples-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-lua-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-lua-debuginfo-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"bcc-tools-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbcc0-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbcc0-debuginfo-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python2-bcc-0.12.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-bcc-0.12.0-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bcc-debuginfo / bcc-debugsource / bcc-devel / bcc-examples / etc");
}
