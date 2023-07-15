#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-776.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74808);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277", "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280");
  script_bugtraq_id(56542, 56543, 56544, 56545, 56546, 56547, 56554);

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2013:0367-1)");
  script_summary(english:"Check for the openSUSE-2012-776 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Flash Player was updated to 11.2.202.251 (bnc#788450), fixing severe
security issues :

  - CVE-2012-5274, CVE-2012-5275, CVE-2012-5276,
    CVE-2012-5277, CVE-2012-5278, CVE-2012-5279,
    CVE-2012-5280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-11/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-02/msg00090.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
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

if ( rpm_check(release:"SUSE12.1", reference:"flash-player-11.2.202.251-34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-gnome-11.2.202.251-34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-kde4-11.2.202.251-34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-11.2.202.251-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-gnome-11.2.202.251-1.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-kde4-11.2.202.251-1.10.1") ) flag++;

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
