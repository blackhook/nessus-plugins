#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-783.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86965);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8025");

  script_name(english:"openSUSE Security Update : xscreensaver (openSUSE-2015-783)");
  script_summary(english:"Check for the openSUSE-2015-783 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xscreensaver was updated to fix one security issue.

The following vulnerability was fixed :

  - CVE-2015-8025: xscreensaver could be bypassed by
    disconnecting HDMI cable (bsc#952062)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xscreensaver packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-data-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-data-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-data-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xscreensaver-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-data-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-data-debuginfo-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-data-extra-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-data-extra-debuginfo-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-debuginfo-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xscreensaver-debugsource-5.22-2.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-data-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-data-debuginfo-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-data-extra-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-data-extra-debuginfo-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-debuginfo-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xscreensaver-debugsource-5.29-2.4.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-data-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-data-debuginfo-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-data-extra-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-data-extra-debuginfo-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-debuginfo-5.33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xscreensaver-debugsource-5.33-4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xscreensaver / xscreensaver-data / xscreensaver-data-debuginfo / etc");
}
