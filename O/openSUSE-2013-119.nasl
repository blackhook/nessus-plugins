#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-119.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74890);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642", "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649", "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368", "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373", "CVE-2013-1374");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2013:0295-2)");
  script_summary(english:"Check for the openSUSE-2013-119 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe Flash Player was updated to 11.2.202.270: (bnc#803485)

  - APSB13-05, CVE-2013-1372, CVE-2013-0645, CVE-2013-1373,
    CVE-2013-1369, CVE-2013-1370, CVE-2013-1366,
    CVE-2013-0649, CVE-2013-1365, CVE-2013-1374,
    CVE-2013-1368, CVE-2013-0642, CVE-2013-0644,
    CVE-2013-0647, CVE-2013-1367, CVE-2013-0639,
    CVE-2013-0638, CVE-2013-0637

    More information can be found on:
    http://www.adobe.com/support/security/bulletins/apsb13-0
    5.html"
  );
  # http://www.adobe.com/support/security/bulletins/apsb13-05.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.adobe.com/support/security/bulletins/apsb13-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-02/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-02/msg00091.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
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

if ( rpm_check(release:"SUSE12.1", reference:"flash-player-11.2.202.270-50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-gnome-11.2.202.270-50.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-kde4-11.2.202.270-50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-11.2.202.270-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-gnome-11.2.202.270-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-kde4-11.2.202.270-1.26.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
