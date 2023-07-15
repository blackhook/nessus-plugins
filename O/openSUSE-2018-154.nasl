#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-154.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106741);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5131", "CVE-2017-15412", "CVE-2017-5130");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2018-154)");
  script_summary(english:"Check for the openSUSE-2018-154 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxml2 fixes three security issues :

  - CVE-2017-15412: Prevent use after free when calling
    XPath extension functions that allowed remote attackers
    to cause DoS or potentially RCE (bsc#1077993)

  - CVE-2016-5131: Use-after-free vulnerability in libxml2
    allowed remote attackers to cause a denial of service or
    possibly have unspecified other impact via vectors
    related to the XPointer range-to function. (bsc#1078813)

  - CVE-2017-5130: Fixed a potential remote buffer overflow
    in function xmlMemoryStrdup() (bsc#1078806)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libxml2-2-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxml2-2-debuginfo-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxml2-debugsource-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxml2-devel-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxml2-tools-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libxml2-tools-debuginfo-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libxml2-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libxml2-debuginfo-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-libxml2-debugsource-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.4-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.4-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-32bit / libxml2-2-debuginfo / etc");
}
