#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-974.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102812);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-8288");

  script_name(english:"openSUSE Security Update : gnome-shell (openSUSE-2017-974)");
  script_summary(english:"Check for the openSUSE-2017-974 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gnome-shell provides the following fixes :

  - Fix not intuitive login screen for root user
    (bsc#1047262)

  - Disable session selection button when it's hidden in
    user switch dialog (bsc#1034584, bsc#1034827)

  - Fix app windows overlay app list in overview screen
    (bsc#1008539)

  - Properly handle failures when loading extensions
    (bsc#1036494, CVE-2017-8288)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047262"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-shell packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-browser-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-browser-plugin-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-browser-plugin-debuginfo-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-calendar-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-calendar-debuginfo-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-debuginfo-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-debugsource-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-devel-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gnome-shell-lang-3.20.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-browser-plugin-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-browser-plugin-debuginfo-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-calendar-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-calendar-debuginfo-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-debuginfo-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-debugsource-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-devel-3.20.4-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-lang-3.20.4-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-shell / gnome-shell-browser-plugin / etc");
}
