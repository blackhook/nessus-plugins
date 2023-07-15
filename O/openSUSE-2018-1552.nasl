#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1552.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119711);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id(
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19409",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477"
  );
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2018-1552)");
  script_summary(english:"Check for the openSUSE-2018-1552 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript to version 9.26 fixes the following 
issues :

Security issues fixed :

  - CVE-2018-19475: Fixed bypass of an intended access
    restriction in psi/zdevice2.c (bsc#1117327)

  - CVE-2018-19476: Fixed bypass of an intended access
    restriction in psi/zicc.c (bsc#1117313)

  - CVE-2018-19477: Fixed bypass of an intended access
    restriction in psi/zfjbig2.c (bsc#1117274)

  - CVE-2018-19409: Check if another device is used
    correctly in LockSafetyParams (bsc#1117022)

  - CVE-2018-18284: Fixed potential sandbox escape through
    1Policy operator (bsc#1112229)

  - CVE-2018-18073: Fixed leaks through operator in saved
    execution stacks (bsc#1111480)

  - CVE-2018-17961: Fixed a -dSAFER sandbox escape by
    bypassing executeonly (bsc#1111479)

  - CVE-2018-17183: Fixed a potential code injection by
    specially crafted PostScript files (bsc#1109105)

Version update to 9.26 (bsc#1117331) :

  - Security issues have been the primary focus

  - Minor bug fixes and improvements

  - For release summary see:
    http://www.ghostscript.com/doc/9.26/News.htm

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117331"
  );
  # http://www.ghostscript.com/doc/9.26/News.htm
  script_set_attribute(attribute:"see_also", value:"https://www.ghostscript.com/doc/9.26/News.htm");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117331");
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspectre1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-debuginfo-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-debugsource-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-devel-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-mini-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-mini-debuginfo-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-mini-debugsource-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-mini-devel-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-x11-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ghostscript-x11-debuginfo-9.26-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libspectre-debugsource-0.2.8-lp150.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libspectre-devel-0.2.8-lp150.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libspectre1-0.2.8-lp150.2.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libspectre1-debuginfo-0.2.8-lp150.2.6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
