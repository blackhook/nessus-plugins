#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-696.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/28");

  script_cve_id("CVE-2019-18348", "CVE-2019-9674");

  script_name(english:"openSUSE Security Update : python (openSUSE-2020-696)");
  script_summary(english:"Check for the openSUSE-2020-696 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python fixes the following issues :

Security issues fixed :

  - CVE-2019-18348: Fixed a CRLF injection via the host part
    of the url passed to urlopen(). Now an InvalidURL
    exception is raised (bsc#1155094).

  - CVE-2019-9674: Improved the documentation to reflect the
    dangers of zip-bombs (bsc#1162825).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162825"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18348");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");
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

if ( rpm_check(release:"SUSE15.1", reference:"libpython2_7-1_0-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpython2_7-1_0-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-base-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-base-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-base-debugsource-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-curses-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-curses-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-debugsource-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-demo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-devel-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-doc-pdf-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-gdbm-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-gdbm-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-idle-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-tk-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-tk-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-xml-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-xml-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python-32bit-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python-32bit-debuginfo-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python-base-32bit-2.7.17-lp151.10.17.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python-base-32bit-debuginfo-2.7.17-lp151.10.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython2_7-1_0 / libpython2_7-1_0-debuginfo / python-base / etc");
}
