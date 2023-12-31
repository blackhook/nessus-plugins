#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91941);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-3100");

  script_name(english:"openSUSE Security Update : kinit (openSUSE-2016-821)");
  script_summary(english:"Check for the openSUSE-2016-821 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kinit was updated to fix one security issue.

This security issue was fixed :

  - CVE-2016-3100: World readable Xauthority file exposed
    cookie credentials (boo#983926)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983926"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kinit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kinit-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"kinit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kinit-debuginfo-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kinit-debugsource-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kinit-devel-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kinit-lang-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kinit-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kinit-debuginfo-32bit-5.11.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kinit-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kinit-debuginfo-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kinit-debugsource-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kinit-devel-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kinit-lang-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kinit-32bit-5.21.0-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kinit-debuginfo-32bit-5.21.0-15.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kinit-32bit / kinit / kinit-debuginfo-32bit / kinit-debuginfo / etc");
}
