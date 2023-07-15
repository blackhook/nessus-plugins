#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1861.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142628);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-17489");

  script_name(english:"openSUSE Security Update : gnome-settings-daemon / gnome-shell (openSUSE-2020-1861)");
  script_summary(english:"Check for the openSUSE-2020-1861 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gnome-settings-daemon, gnome-shell fixes the following
issues :

gnome-settings-daemon :

  - Add support for recent UCM related changes in ALSA and
    PulseAudio. (jsc#SLE-16518)

  - Don't warn when a default source or sink is missing and
    the PulseAudio daemon is restarting. (jsc#SLE-16518)

  - Don't warn about starting/stopping services which don't
    exist. (bsc#1172760).

gnome-shell :

  - Add support for recent UCM related changes in ALSA and
    PulseAudio. (jsc#SLE-16518)

  - CVE-2020-17489: reset auth prompt on vt switch before
    fade in in loginDialog (bsc#1175155).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175155"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gnome-settings-daemon / gnome-shell packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17489");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-settings-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-settings-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-settings-daemon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-settings-daemon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-settings-daemon-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gnome-settings-daemon-3.34.2+0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-settings-daemon-debuginfo-3.34.2+0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-settings-daemon-debugsource-3.34.2+0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-settings-daemon-devel-3.34.2+0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-settings-daemon-lang-3.34.2+0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-calendar-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-calendar-debuginfo-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-debuginfo-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-debugsource-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-devel-3.34.5-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gnome-shell-lang-3.34.5-lp152.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-settings-daemon / gnome-settings-daemon-debuginfo / etc");
}
