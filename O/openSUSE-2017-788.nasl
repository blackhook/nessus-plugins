#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-788.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101285);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5953", "CVE-2017-6349", "CVE-2017-6350");

  script_name(english:"openSUSE Security Update : vim (openSUSE-2017-788)");
  script_summary(english:"Check for the openSUSE-2017-788 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vim fixes the following issues :

Security issues fixed :

  - CVE-2017-5953: Fixed a possible overflow with corrupted
    spell file (bsc#1024724)

  - CVE-2017-6350: Fixed a possible overflow when reading a
    corrupted undo file (bsc#1027053)

  - CVE-2017-6349: Fixed a possible overflow when reading a
    corrupted undo file (bsc#1027057)

Non security issues fixed :

  - Speed up YAML syntax highlighting (bsc#1018870)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027057"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gvim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"gvim-7.4.326-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gvim-debuginfo-7.4.326-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"vim-7.4.326-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"vim-data-7.4.326-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"vim-debuginfo-7.4.326-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"vim-debugsource-7.4.326-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvim / gvim-debuginfo / vim / vim-data / vim-debuginfo / etc");
}
