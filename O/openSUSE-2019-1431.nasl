#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1431.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125330);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/29 10:47:07");

  script_cve_id("CVE-2018-15587");

  script_name(english:"openSUSE Security Update : evolution (openSUSE-2019-1431)");
  script_summary(english:"Check for the openSUSE-2019-1431 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for evolution fixes the following issues :

Security issue fixed :

  - CVE-2018-15587: Fixed an issue with spoofed pgp
    signatures by using specially crafted emails
    (bsc#1125230).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125230"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-bogofilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-bogofilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-pst-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-pst-import-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-plugin-spamassassin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glade-catalog-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glade-catalog-evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"evolution-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-debuginfo-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-debugsource-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-devel-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-lang-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-bogofilter-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-bogofilter-debuginfo-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-pst-import-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-pst-import-debuginfo-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-spamassassin-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evolution-plugin-spamassassin-debuginfo-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"glade-catalog-evolution-3.26.6-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"glade-catalog-evolution-debuginfo-3.26.6-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-debuginfo / evolution-debugsource / etc");
}
