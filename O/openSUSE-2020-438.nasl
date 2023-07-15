#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-438.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135163);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/06");

  script_cve_id("CVE-2017-1000231", "CVE-2017-1000232");

  script_name(english:"openSUSE Security Update : ldns (openSUSE-2020-438)");
  script_summary(english:"Check for the openSUSE-2020-438 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ldns fixes the following issues :

  - CVE-2017-1000231: Fixed a buffer overflow during token
    parsing (bsc#1068711).

  - CVE-2017-1000232: Fixed a double-free vulnerability in
    str2host.c (bsc#1068709).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068711"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ldns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldns2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldns2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-DNS-LDNS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-DNS-LDNS-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");
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

if ( rpm_check(release:"SUSE15.1", reference:"ldns-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ldns-debuginfo-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ldns-debugsource-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ldns-devel-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libldns2-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libldns2-debuginfo-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-DNS-LDNS-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-DNS-LDNS-debuginfo-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-ldns-1.7.0-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-ldns-debuginfo-1.7.0-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldns / ldns-debuginfo / ldns-debugsource / ldns-devel / libldns2 / etc");
}
