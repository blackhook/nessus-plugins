#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-715.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149530);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2016-6209", "CVE-2020-13977");

  script_name(english:"openSUSE Security Update : nagios (openSUSE-2021-715)");
  script_summary(english:"Check for the openSUSE-2021-715 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nagios fixes the following issues :

  - new nagios-exec-start-post script to fix boo#1003362

  - fix nagios_upgrade.sh writing to log file in user
    controlled directory (boo#1182398). The
    nagios_upgrade.sh script writes the logfile directly
    below /var/log/ 

nagios was updated to 4.4.6 :

  - Fixed Map display in Internet Explorer 11 (#714)

  - Fixed duplicate properties appearing in statusjson.cgi
    (#718)

  - Fixed NERD not building when enabled in ./configure
    (#723)

  - Fixed build process when using GCC 10 (#721)

  - Fixed postauth vulnerabilities in histogram.js, map.js,
    trends.js (CVE-2020-13977, boo#1172794)

  - When using systemd, configuration will be verified
    before reloading (#715)

  - Fixed HARD OK states triggering on the maximum check
    attempt (#757)

  - Fix for CVE-2016-6209 (boo#989759) - The 'corewindow'
    parameter (as in bringing this to our attention go to
    Dawid Golunski (boo#1014637)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989759"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nagios packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-theme-exfoliation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-dch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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

if ( rpm_check(release:"SUSE15.2", reference:"nagios-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-contrib-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-debuginfo-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-debugsource-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-devel-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-theme-exfoliation-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-www-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-www-dch-4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nagios-www-debuginfo-4.4.6-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-contrib / nagios-debuginfo / nagios-debugsource / etc");
}
