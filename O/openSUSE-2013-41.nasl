#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-41.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74997);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-6096");

  script_name(english:"openSUSE Security Update : nagios (openSUSE-SU-2013:0140-1)");
  script_summary(english:"Check for the openSUSE-2013-41 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - avoid stack based buffer overflow in web interface
    (history): added nagios-history_buffer_overflow.patch -
    (bnc#797237) fixes CVE-2012-6096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-01/msg00033.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nagios packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios3 history.cgi Host Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"nagios-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-debuginfo-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-debugsource-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-devel-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-www-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"nagios-www-debuginfo-3.3.1-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-3.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debuginfo-3.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-debugsource-3.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-devel-3.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-3.4.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"nagios-www-debuginfo-3.4.1-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-debuginfo / nagios-debugsource / nagios-devel / etc");
}
