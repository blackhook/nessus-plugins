#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-62.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106222);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12904");

  script_name(english:"openSUSE Security Update : newsbeuter (openSUSE-2018-62)");
  script_summary(english:"Check for the openSUSE-2018-62 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for newsbeuter fixes one issues.

This security issue was fixed :

  - CVE-2017-12904: Improper neutralization of special
    elements allowed remote attackers to perform
    user-assisted code execution by crafting an RSS item
    that includes shell code in its title and/or URL
    (bsc#1054578)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054578"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected newsbeuter packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:newsbeuter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:newsbeuter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:newsbeuter-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:newsbeuter-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"newsbeuter-2.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"newsbeuter-debuginfo-2.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"newsbeuter-debugsource-2.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"newsbeuter-lang-2.9-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"newsbeuter-2.9-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"newsbeuter-debuginfo-2.9-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"newsbeuter-debugsource-2.9-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"newsbeuter-lang-2.9-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "newsbeuter / newsbeuter-debuginfo / newsbeuter-debugsource / etc");
}
