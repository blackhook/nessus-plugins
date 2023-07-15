#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-697.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74775);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-5248", "CVE-2012-5249", "CVE-2012-5250", "CVE-2012-5251", "CVE-2012-5252", "CVE-2012-5253", "CVE-2012-5254", "CVE-2012-5255", "CVE-2012-5256", "CVE-2012-5257", "CVE-2012-5258", "CVE-2012-5259", "CVE-2012-5260", "CVE-2012-5261", "CVE-2012-5262", "CVE-2012-5263", "CVE-2012-5264", "CVE-2012-5265", "CVE-2012-5266", "CVE-2012-5267", "CVE-2012-5268", "CVE-2012-5269", "CVE-2012-5270", "CVE-2012-5271", "CVE-2012-5272");
  script_bugtraq_id(56198, 56200, 56201, 56202, 56203, 56204, 56205, 56206, 56207, 56208, 56209, 56210, 56211, 56212, 56213, 56214, 56215, 56216, 56217, 56218, 56219, 56220, 56221, 56222, 56224);

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2013:0370-1)");
  script_summary(english:"Check for the openSUSE-2012-697 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Flash Player was updated to 11.2.202.243

  - CVE-2012-5248, CVE-2012-5249, CVE-2012-5250,
    CVE-2012-5251, CVE-2012-5252, CVE-2012-5253,
    CVE-2012-5254, CVE-2012-5255, CVE-2012-5256,
    CVE-2012-5257, CVE-2012-5258, CVE-2012-5259,
    CVE-2012-5260, CVE-2012-5261, CVE-2012-5262,
    CVE-2012-5263, CVE-2012-5264, CVE-2012-5265,
    CVE-2012-5266, CVE-2012-5267, CVE-2012-5268,
    CVE-2012-5269, CVE-2012-5270, CVE-2012-5271,
    CVE-2012-5272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-10/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2013-02/msg00096.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
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

if ( rpm_check(release:"SUSE12.1", reference:"flash-player-11.2.202.243-30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-gnome-11.2.202.243-30.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"flash-player-kde4-11.2.202.243-30.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-11.2.202.243-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-gnome-11.2.202.243-1.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"flash-player-kde4-11.2.202.243-1.6.1") ) flag++;

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
