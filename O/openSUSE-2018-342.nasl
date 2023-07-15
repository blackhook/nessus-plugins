#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-342.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108934);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12194");

  script_name(english:"openSUSE Security Update : spice-gtk (openSUSE-2018-342)");
  script_summary(english:"Check for the openSUSE-2018-342 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for spice-gtk fixes the following issues :

  - CVE-2017-12194: A flaw was found in the way spice-client
    processed certain messages sent from the server. An
    attacker, having control of malicious spice-server,
    could use this flaw to crash the client or execute
    arbitrary code with permissions of the user running the
    client. spice-gtk versions through 0.34 are believed to
    be vulnerable. (bsc#1085415)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085415"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spice-gtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-2_0-8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-glib-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-client-gtk-3_0-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-controller0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspice-controller0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spice-gtk-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-SpiceClientGlib-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-SpiceClientGtk-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-glib-2_0-8-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-glib-2_0-8-debuginfo-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-glib-helper-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-glib-helper-debuginfo-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-gtk-3_0-5-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-client-gtk-3_0-5-debuginfo-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-controller0-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspice-controller0-debuginfo-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spice-gtk-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spice-gtk-debuginfo-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spice-gtk-debugsource-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spice-gtk-devel-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spice-gtk-lang-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-SpiceClientGlib-2_0-0.33-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-SpiceClientGtk-3_0-0.33-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libspice-client-glib-2_0-8 / libspice-client-glib-2_0-8-debuginfo / etc");
}
