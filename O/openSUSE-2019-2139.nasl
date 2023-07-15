#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2139.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128869);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/21");

  script_cve_id("CVE-2019-10216");
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"openSUSE Security Update : ghostscript (openSUSE-2019-2139)");
  script_summary(english:"Check for the openSUSE-2019-2139 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript fixes the following issues :

Security issue fixed :

  - CVE-2019-10216: Fix privilege escalation via specially
    crafted PostScript file (bsc#1144621).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144621");
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10216");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-debuginfo-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-debugsource-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-devel-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-mini-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-mini-debuginfo-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-mini-debugsource-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-mini-devel-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-x11-9.26a-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ghostscript-x11-debuginfo-9.26a-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}
