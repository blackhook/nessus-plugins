#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-857.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111638);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18199", "CVE-2017-18201");

  script_name(english:"openSUSE Security Update : libcdio (openSUSE-2018-857)");
  script_summary(english:"Check for the openSUSE-2018-857 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libcdio fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2017-18199: Fixed a NULL pointer dereference in
    realloc_symlink in rock.c (bsc#1082821)

  - CVE-2017-18201: Fixed a double free vulnerability in
    get_cdtext_generic() in _cdio_generic.c (bsc#1082877)

  - Fixed several memory leaks (bsc#1082821)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082877"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libcdio packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cdio-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cdio-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cdio-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio++0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio++0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio++0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio++0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio16-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcdio16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiso9660-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiso9660-10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiso9660-10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libiso9660-10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libcdio++0-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcdio++0-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcdio-debugsource-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcdio-devel-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcdio16-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcdio16-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libiso9660-10-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libiso9660-10-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudf0-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libudf0-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"cdio-utils-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"cdio-utils-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"cdio-utils-debugsource-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcdio++0-32bit-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcdio++0-32bit-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcdio16-32bit-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcdio16-32bit-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libiso9660-10-32bit-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libiso9660-10-32bit-debuginfo-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libudf0-32bit-0.94-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libudf0-32bit-debuginfo-0.94-lp150.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cdio-utils / cdio-utils-debuginfo / cdio-utils-debugsource / etc");
}
