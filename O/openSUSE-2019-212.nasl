#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-212.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122395);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-20230");

  script_name(english:"openSUSE Security Update : pspp / spread-sheet-widget (openSUSE-2019-212)");
  script_summary(english:"Check for the openSUSE-2019-212 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pspp to version 1.2.0 fixes the following issues :

Security issue fixed :

  - CVE-2018-20230: Fixed a heap-based buffer overflow in
    read_bytes_internal function that could lead to
    denial-of-service (bsc#1120061).

Other bug fixes and changes :

  - Add upstream patch to avoid compiling with old Texinfo
    4.13.

  - New experimental command SAVE DATA COLLECTION to save
    MDD files.

  - MTIME and YMDHMS variable formats now supported.

  - Spread sheet rendering now done via spread-sheet-widget.

This update introduces a new package called spread-sheet-widget as
dependency."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120061"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pspp / spread-sheet-widget packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspread-sheet-widget0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspread-sheet-widget0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pspp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spread-sheet-widget-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spread-sheet-widget-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libspread-sheet-widget0-0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libspread-sheet-widget0-debuginfo-0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spread-sheet-widget-debugsource-0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"spread-sheet-widget-devel-0.3-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pspp-1.2.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pspp-debuginfo-1.2.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pspp-debugsource-1.2.0-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"pspp-devel-1.2.0-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libspread-sheet-widget0 / libspread-sheet-widget0-debuginfo / etc");
}
