#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-367.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109067);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000159");

  script_name(english:"openSUSE Security Update : evince (openSUSE-2018-367)");
  script_summary(english:"Check for the openSUSE-2018-367 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for evince fixes the following issues :

  - CVE-2017-1000159: Command injection in evince via
    filename when printing to PDF could lead to command
    execution (bsc#1070046)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070046"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-browser-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-comicsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-comicsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-djvudocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-djvudocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-dvidocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-dvidocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-pdfdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-pdfdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-psdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-psdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-tiffdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-tiffdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-xpsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-xpsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevdocument3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevdocument3-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevview3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevview3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EvinceDocument-3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EvinceView-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/17");
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

if ( rpm_check(release:"SUSE42.3", reference:"evince-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-browser-plugin-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-browser-plugin-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-debugsource-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-devel-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-lang-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-comicsdocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-comicsdocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-djvudocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-djvudocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-dvidocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-dvidocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-pdfdocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-pdfdocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-psdocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-psdocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-tiffdocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-tiffdocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-xpsdocument-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-xpsdocument-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevdocument3-4-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevdocument3-4-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevview3-3-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevview3-3-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-evince-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-evince-debuginfo-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-EvinceDocument-3_0-3.20.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-EvinceView-3_0-3.20.2-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-browser-plugin-debuginfo / etc");
}
