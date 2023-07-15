#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1144.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118110);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16741", "CVE-2018-16742", "CVE-2018-16743", "CVE-2018-16744", "CVE-2018-16745");

  script_name(english:"openSUSE Security Update : mgetty (openSUSE-2018-1144)");
  script_summary(english:"Check for the openSUSE-2018-1144 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mgetty fixes the following issues :

  - CVE-2018-16741: Fixed a command injection in
    fax/faxq-helper.c (boo#1108752)

  - CVE-2018-16742: Stack-based buffer overflow in
    contrib/scrts.c triggered via command line parameter
    (boo#1108762)

  - CVE-2018-16743: Stack-based buffer overflow with long
    username in contrib/next-login/login.c (boo#1108761)

  - CVE-2018-16744: Command injection in faxrec.c
    (boo#1108757)

  - CVE-2018-16745: Stack-based buffer overflow in
    fax_notify_mail() in faxrec.c (boo#1108756)

  - sets maximum length of a string to prevent buffer
    overflow and thus possible command injection

  - The obsolete contrib/scrts.c tool was deleted, which
    contained a buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108762"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mgetty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:g3utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:g3utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgetty-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mgetty-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sendfax-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/15");
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

if ( rpm_check(release:"SUSE42.3", reference:"g3utils-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"g3utils-debuginfo-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mgetty-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mgetty-debuginfo-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mgetty-debugsource-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sendfax-1.1.36-65.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sendfax-debuginfo-1.1.36-65.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "g3utils / g3utils-debuginfo / mgetty / mgetty-debuginfo / etc");
}
