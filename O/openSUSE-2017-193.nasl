#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-193.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96944);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6271");

  script_name(english:"openSUSE Security Update : bzrtp (openSUSE-2017-193)");
  script_summary(english:"Check for the openSUSE-2017-193 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bzrtp fixes one security issue.

The following vulnerability was fixed :

  - CVE-2016-6271: missing HVI check on DHPart2 packet
    reception may have allowed man-in-the-middle attackers
    to conduct spoofing attacks boo#1020844)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020844"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzrtp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bzrtp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bzrtp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbzrtp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbzrtp0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbzrtp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbzrtp0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"bzrtp-debugsource-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"bzrtp-devel-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libbzrtp0-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libbzrtp0-debuginfo-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libbzrtp0-32bit-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libbzrtp0-debuginfo-32bit-1.0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bzrtp-debugsource-1.0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bzrtp-devel-1.0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libbzrtp0-1.0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libbzrtp0-debuginfo-1.0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libbzrtp0-32bit-1.0.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libbzrtp0-debuginfo-32bit-1.0.3-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzrtp-debugsource / bzrtp-devel / libbzrtp0 / libbzrtp0-32bit / etc");
}
