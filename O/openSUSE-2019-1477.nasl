#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1477.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125619);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2018-16868");

  script_name(english:"openSUSE Security Update : gnutls (openSUSE-2019-1477)");
  script_summary(english:"Check for the openSUSE-2019-1477 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gnutls fixes the following issues :

Security issue fixed :

  - CVE-2018-16868: Fixed Bleichenbacher-like side channel
    leakage in PKCS#1 v1.5 verification (bsc#1118087).

Non-security issue fixed :

  - Explicitly require libnettle 3.4.1 to prevent missing
    symbol errors (bsc#1134856).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134856"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE15.1", reference:"gnutls-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-debuginfo-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-debugsource-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-guile-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-guile-debuginfo-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane-devel-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane0-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane0-debuginfo-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-devel-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls30-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls30-debuginfo-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx-devel-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx28-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx28-debuginfo-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-debugsource / gnutls-guile / etc");
}
