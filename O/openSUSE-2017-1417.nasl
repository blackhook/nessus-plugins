#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1417.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105456);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000083");

  script_name(english:"openSUSE Security Update : evince (openSUSE-2017-1417)");
  script_summary(english:"Check for the openSUSE-2017-1417 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for evince fixes the following issues :

Security issue fixed :

  - CVE-2017-1000083: Remove support for tar and tar-like
    commands in comics backend (bsc#1046856).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046856"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Evince CBT File Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"evince-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-browser-plugin-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-browser-plugin-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-debugsource-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-devel-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-lang-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-comicsdocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-comicsdocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-djvudocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-djvudocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-dvidocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-dvidocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-pdfdocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-pdfdocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-psdocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-psdocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-tiffdocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-tiffdocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-xpsdocument-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"evince-plugin-xpsdocument-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libevdocument3-4-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libevdocument3-4-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libevview3-3-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libevview3-3-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nautilus-evince-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nautilus-evince-debuginfo-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"typelib-1_0-EvinceDocument-3_0-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"typelib-1_0-EvinceView-3_0-3.20.2-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-browser-plugin-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-browser-plugin-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-debugsource-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-devel-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-lang-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-comicsdocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-comicsdocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-djvudocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-djvudocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-dvidocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-dvidocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-pdfdocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-pdfdocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-psdocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-psdocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-tiffdocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-tiffdocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-xpsdocument-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"evince-plugin-xpsdocument-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevdocument3-4-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevdocument3-4-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevview3-3-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libevview3-3-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-evince-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-evince-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-EvinceDocument-3_0-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-EvinceView-3_0-3.20.2-6.1") ) flag++;

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
