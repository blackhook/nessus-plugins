#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-938.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102557);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12678");

  script_name(english:"openSUSE Security Update : taglib (openSUSE-2017-938)");
  script_summary(english:"Check for the openSUSE-2017-938 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for taglib fixes the following issues :

  - CVE-2017-12678: Denial of service vulnerability via
    specially crafted ID3v2 data (boo#1052699)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052699"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected taglib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag_c0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag_c0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag_c0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtag_c0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:taglib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:taglib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:taglib-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libtag-devel-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtag1-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtag1-debuginfo-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtag_c0-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtag_c0-debuginfo-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"taglib-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"taglib-debuginfo-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"taglib-debugsource-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtag1-32bit-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtag1-debuginfo-32bit-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtag_c0-32bit-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtag_c0-debuginfo-32bit-1.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtag-devel-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtag1-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtag1-debuginfo-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtag_c0-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtag_c0-debuginfo-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"taglib-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"taglib-debuginfo-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"taglib-debugsource-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtag1-32bit-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtag1-debuginfo-32bit-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtag_c0-32bit-1.11-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtag_c0-debuginfo-32bit-1.11-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtag-devel / libtag1 / libtag1-32bit / libtag1-debuginfo / etc");
}
