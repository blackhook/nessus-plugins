#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-177.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74915);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-SU-2013:0405-1)");
  script_summary(english:"Check for the openSUSE-2013-177 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pidgin was updated to fix security issues :

  - Fix a crash when receiving UPnP responses with
    abnormally long values. (CVE-2013-0274)

  - Fix a crash in Sametime when a malicious server sends us
    an abnormally long user ID. (CVE-2013-0273)

  - Fix a bug where the MXit server or a man-in-the-middle
    could potentially send specially crafted data that could
    overflow a buffer and lead to a crash or remote code
    execution.(CVE-2013-0272)

  - Fix a bug where a remote MXit user could possibly
    specify a local file path to be written to.
    (CVE-2013-0271)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-03/msg00016.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/27");
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

if ( rpm_check(release:"SUSE12.1", reference:"finch-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"finch-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"finch-devel-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-branding-upstream-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-devel-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-lang-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-meanwhile-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-meanwhile-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-tcl-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libpurple-tcl-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-debugsource-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-devel-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-evolution-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"pidgin-evolution-debuginfo-2.10.1-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"finch-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"finch-debuginfo-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"finch-devel-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-branding-upstream-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-debuginfo-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-devel-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-lang-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-meanwhile-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-meanwhile-debuginfo-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-tcl-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpurple-tcl-debuginfo-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-debuginfo-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-debugsource-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-devel-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-evolution-2.10.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pidgin-evolution-debuginfo-2.10.6-1.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
