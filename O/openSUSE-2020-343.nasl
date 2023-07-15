#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-343.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134619);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/18");

  script_cve_id("CVE-2019-20446");

  script_name(english:"openSUSE Security Update : librsvg (openSUSE-2020-343)");
  script_summary(english:"Check for the openSUSE-2020-343 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for librsvg to version 2.42.8 fixes the following issues :

librsvg was updated to version 2.42.8 fixing the following issues:&#9; 

  - CVE-2019-20446: Fixed an issue where a crafted SVG file
    with nested patterns can cause denial of service
    (bsc#1162501). NOTE: Librsvg now has limits on the
    number of loaded XML elements, and the number of
    referenced elements within an SVG document. 

  - Fixed a stack exhaustion with circular references in
    <use> elements.

  - Fixed a denial-of-service condition from exponential
    explosion of rendered elements, through nested use of
    SVG 'use' elements in malicious SVGs. 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162501"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected librsvg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-view-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Rsvg-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"gdk-pixbuf-loader-rsvg-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librsvg-2-2-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librsvg-2-2-debuginfo-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librsvg-debugsource-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"librsvg-devel-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rsvg-thumbnailer-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rsvg-view-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rsvg-view-debuginfo-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-Rsvg-2_0-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-debuginfo-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.42.8-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"librsvg-2-2-32bit-debuginfo-2.42.8-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-loader-rsvg / gdk-pixbuf-loader-rsvg-debuginfo / etc");
}
