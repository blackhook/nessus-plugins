#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-780.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(137229);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/13");

  script_cve_id("CVE-2017-8834", "CVE-2017-8871");

  script_name(english:"openSUSE Security Update : libcroco (openSUSE-2020-780)");
  script_summary(english:"Check for the openSUSE-2020-780 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libcroco fixes the following issues :

Security issues fixed :

  - CVE-2017-8834: Fixed denial of service (memory
    allocation error) via a crafted CSS file (bsc#1043898).

  - CVE-2017-8871: Fixed denial of service (infinite loop
    and CPU consumption) via a crafted CSS file
    (bsc#1043899). 

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043899"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libcroco packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-0_6-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-0_6-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-0_6-3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-0_6-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcroco-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"libcroco-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcroco-0_6-3-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcroco-0_6-3-debuginfo-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcroco-debuginfo-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcroco-debugsource-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcroco-devel-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libcroco-0_6-3-32bit-0.6.12-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libcroco-0_6-3-32bit-debuginfo-0.6.12-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcroco / libcroco-0_6-3 / libcroco-0_6-3-debuginfo / etc");
}
