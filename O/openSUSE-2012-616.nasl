#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-616.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74758);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-3547");

  script_name(english:"openSUSE Security Update : freeradius (openSUSE-SU-2012:1200-1)");
  script_summary(english:"Check for the openSUSE-2012-616 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of freeradius fixes a stack overflow in TLS handling,
which can be exploited by remote attackers able to access Radius to
execute code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-09/msg00076.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-dialupadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-debuginfo-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-debugsource-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-devel-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-dialupadmin-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-libs-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-libs-debuginfo-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-utils-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freeradius-server-utils-debuginfo-2.1.12-4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-debuginfo-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-debugsource-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-devel-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-dialupadmin-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-libs-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-libs-debuginfo-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-utils-2.1.12-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"freeradius-server-utils-debuginfo-2.1.12-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius");
}
