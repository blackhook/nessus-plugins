#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-55.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74528);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2011-55)");
  script_summary(english:"Check for the openSUSE-2011-55 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - specially crafted requests could bypass RewriteRule and
    ProxyPassMatch

  - new template file:
    /etc/apache2/vhosts.d/vhost-ssl.template allow TLSv1
    only, browser match stuff commented out.

  - rc script /etc/init.d/apache2: handle reload with
    deleted binaries by message to stdout only, but refrain
    from sending signals."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/29");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"apache2-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-debuginfo-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-debugsource-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-devel-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-event-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-event-debuginfo-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-example-pages-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-itk-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-itk-debuginfo-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-prefork-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-prefork-debuginfo-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-utils-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-utils-debuginfo-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-worker-2.2.21-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-worker-debuginfo-2.2.21-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
