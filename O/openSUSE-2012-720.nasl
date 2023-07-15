#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-720.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74787);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-4504", "CVE-2012-4505");

  script_name(english:"openSUSE Security Update : libproxy / libproxy-plugins (openSUSE-SU-2012:1375-1)");
  script_summary(english:"Check for the openSUSE-2012-720 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"This update of libproxy fixed a buffer overflow flaw."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-10/msg00065.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libproxy / libproxy-plugins packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-gnome3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-config-kde4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-networkmanager-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-mozjs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-mozjs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-mozjs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libproxy1-pacrunner-webkit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Net-Libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Net-Libproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libproxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
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

if ( rpm_check(release:"SUSE12.1", reference:"libproxy-debugsource-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy-devel-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy-plugins-debugsource-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy-sharp-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy-tools-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy-tools-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-config-gnome3-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-config-gnome3-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-config-kde4-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-config-kde4-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-networkmanager-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-networkmanager-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-pacrunner-mozjs-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-pacrunner-mozjs-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-pacrunner-webkit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libproxy1-pacrunner-webkit-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-Net-Libproxy-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"perl-Net-Libproxy-debuginfo-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"python-libproxy-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-config-gnome3-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-config-gnome3-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-config-kde4-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-config-kde4-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-networkmanager-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-networkmanager-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-pacrunner-mozjs-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-pacrunner-mozjs-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-debuginfo-32bit-0.4.7-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy-debugsource-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy-devel-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy-sharp-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy-tools-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy-tools-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy1-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libproxy1-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-Net-Libproxy-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-Net-Libproxy-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"python-libproxy-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy-plugins-debugsource-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-32bit-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-config-gnome3-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-config-gnome3-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-config-kde4-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-config-kde4-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-debuginfo-32bit-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-networkmanager-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-networkmanager-debuginfo-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-0.4.7-14.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libproxy1-pacrunner-webkit-debuginfo-0.4.7-14.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libproxy-plugins-debugsource / libproxy1-config-gnome3 / etc");
}
