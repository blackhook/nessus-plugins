#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-458.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76488);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-4616");

  script_name(english:"openSUSE Security Update : python / python3 (openSUSE-SU-2014:0890-1)");
  script_summary(english:"Check for the openSUSE-2014-458 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"python and python3 were updated to fix one security issue.

This security issue was fixed :

  - Missing boundary check in JSON module (CVE-2014-4616)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=884075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-07/msg00015.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python / python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_3m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_3m1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_3m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_3m1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libpython2_7-1_0-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpython2_7-1_0-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpython3_3m1_0-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libpython3_3m1_0-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-base-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-base-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-base-debugsource-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-curses-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-curses-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-debugsource-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-demo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-devel-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-doc-pdf-2.7-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-gdbm-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-gdbm-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-idle-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-tk-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-tk-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-xml-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-xml-debuginfo-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-base-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-base-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-base-debugsource-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-curses-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-curses-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-dbm-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-dbm-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-debugsource-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-devel-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-devel-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-doc-pdf-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-idle-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-testsuite-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-testsuite-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-tk-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-tk-debuginfo-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-tools-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpython3_3m1_0-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libpython3_3m1_0-debuginfo-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python-base-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python-debuginfo-32bit-2.7.3-10.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python3-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python3-base-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python3-base-debuginfo-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.3.0-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpython2_7-1_0-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpython2_7-1_0-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpython3_3m1_0-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpython3_3m1_0-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-debugsource-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-curses-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-curses-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-debugsource-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-demo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-devel-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-doc-pdf-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-gdbm-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-gdbm-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-idle-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tk-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tk-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-xml-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-xml-debuginfo-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-base-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-base-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-base-debugsource-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-curses-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-curses-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-dbm-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-dbm-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-debugsource-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-devel-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-devel-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-doc-pdf-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-idle-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-testsuite-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-testsuite-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-tk-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-tk-debuginfo-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-tools-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython3_3m1_0-32bit-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython3_3m1_0-debuginfo-32bit-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-base-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-debuginfo-32bit-2.7.6-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python3-32bit-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python3-base-32bit-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python3-base-debuginfo-32bit-3.3.5-5.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.3.5-5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python3");
}
