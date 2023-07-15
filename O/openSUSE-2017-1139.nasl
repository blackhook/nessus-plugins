#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103763);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10683");

  script_name(english:"openSUSE Security Update : mpg123 (openSUSE-2017-1139)");
  script_summary(english:"Check for the openSUSE-2017-1139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mpg123 to version 1.25.7 fixes the following issues :

  - CVE-2017-10683: Improvement over previous fix for xrpnt
    overflow problems (boo#1046766)

The following changes are also included in version 1.25.7 :

  - Do not play with cursor and inverse video for progress
    bar when TERM=dumb

  - Fix parsing of host port for numerical IPv6 addresses"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046766"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mpg123 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpg123-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpg123-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpg123-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmpg123-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libout123-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libout123-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libout123-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libout123-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-esound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-esound-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-esound-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-esound-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-jack-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-jack-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-openal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-openal-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-openal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-openal-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-portaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-portaudio-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-portaudio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-portaudio-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-pulse-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-pulse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-pulse-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-sdl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-sdl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mpg123-sdl-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libmpg123-0-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libmpg123-0-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libout123-0-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libout123-0-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-debugsource-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-devel-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-esound-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-esound-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-jack-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-jack-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-openal-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-openal-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-portaudio-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-portaudio-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-pulse-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-pulse-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-sdl-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mpg123-sdl-debuginfo-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmpg123-0-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libmpg123-0-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libout123-0-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libout123-0-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-devel-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-esound-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-esound-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-jack-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-jack-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-openal-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-openal-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-portaudio-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-portaudio-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-pulse-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-pulse-debuginfo-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-sdl-32bit-1.25.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"mpg123-sdl-debuginfo-32bit-1.25.7-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmpg123-0 / libmpg123-0-32bit / libmpg123-0-debuginfo / etc");
}
