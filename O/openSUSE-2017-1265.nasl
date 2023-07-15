#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1265.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104523);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12424");

  script_name(english:"openSUSE Security Update : shadow (openSUSE-2017-1265)");
  script_summary(english:"Check for the openSUSE-2017-1265 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for shadow fixes several issues.

This security issue was fixed :

  - CVE-2017-12424: The newusers tool could have been forced
    to manipulate internal data structures in ways
    unintended by the authors. Malformed input may have lead
    to crashes (with a buffer overflow or other memory
    corruption) or other unspecified behaviors
    (bsc#1052261).

These non-security issues were fixed :

  - bsc#1023895: Fixed man page to not contain invalid
    options and also prevent warnings when using these
    options in certain settings

  - bsc#980486: Reset user in /var/log/tallylog because of
    the usage of pam_tally2

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980486"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shadow packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadow-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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

if ( rpm_check(release:"SUSE42.2", reference:"shadow-4.2.1-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"shadow-debuginfo-4.2.1-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"shadow-debugsource-4.2.1-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"shadow-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"shadow-debuginfo-4.2.1-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"shadow-debugsource-4.2.1-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shadow / shadow-debuginfo / shadow-debugsource");
}
