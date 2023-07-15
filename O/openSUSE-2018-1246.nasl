#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1246.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118382);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7500", "CVE-2017-7501");

  script_name(english:"openSUSE Security Update : rpm (openSUSE-2018-1246)");
  script_summary(english:"Check for the openSUSE-2018-1246 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rpm fixes the following issues :

These security issues were fixed :

  - CVE-2017-7500: rpm did not properly handle RPM
    installations when a destination path was a symbolic
    link to a directory, possibly changing ownership and
    permissions of an arbitrary directory, and RPM files
    being placed in an arbitrary destination (bsc#943457).

  - CVE-2017-7501: rpm used temporary files with predictable
    names when installing an RPM. An attacker with ability
    to write in a directory where files will be installed
    could create symbolic links to an arbitrary location and
    modify content, and possibly permissions to arbitrary
    files, which could be used for denial of service or
    possibly privilege escalation (bsc#943457)

This non-security issue was fixed :

  - Use ksym-provides tool [bsc#1077692]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943457"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-build-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/25");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"python3-rpm-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rpm-debuginfo-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rpm-debugsource-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-build-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-build-debuginfo-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-debuginfo-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-debugsource-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-devel-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-python-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-python-debuginfo-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rpm-python-debugsource-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"rpm-32bit-4.11.2-14.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"rpm-debuginfo-32bit-4.11.2-14.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-rpm / python3-rpm-debuginfo / python3-rpm-debugsource / etc");
}
