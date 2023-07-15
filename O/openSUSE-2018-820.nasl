#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-820.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111585);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-2816", "CVE-2017-2920");

  script_name(english:"openSUSE Security Update : libofx (openSUSE-2018-820)");
  script_summary(english:"Check for the openSUSE-2018-820 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libofx fixes the following issues :

The following security vulnerabilities have been addressed :

  - CVE-2017-2920: Fixed an exploitable buffer overflow in
    the tag parsing functionality, which could result in an
    out of bounds write and could be triggered via a
    specially crafted OFX file (boo#1061964)

  - CVE-2017-2816: Fixed another buffer overflow in the tag
    parsing functionality, which could result in an stack
    overflow and could be triggered via a specially crafted
    OFX file (boo#1058673)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libofx packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libofx6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/08");
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

if ( rpm_check(release:"SUSE42.3", reference:"libofx-0.9.10-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libofx-debuginfo-0.9.10-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libofx-debugsource-0.9.10-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libofx-devel-0.9.10-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libofx6-0.9.10-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libofx6-debuginfo-0.9.10-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libofx / libofx-debuginfo / libofx-debugsource / libofx-devel / etc");
}
