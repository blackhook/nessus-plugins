#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-501.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135449);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/29");

  script_cve_id("CVE-2020-11501");

  script_name(english:"openSUSE Security Update : gmp / gnutls / libnettle (openSUSE-2020-501)");
  script_summary(english:"Check for the openSUSE-2020-501 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gmp, gnutls, libnettle fixes the following issues :

Security issue fixed :

  - CVE-2020-11501: Fixed zero random value in DTLS client
    hello (bsc#1168345)

FIPS related bugfixes :

  - FIPS: Install checksums for binary integrity
    verification which are required when running in FIPS
    mode (bsc#1152692, jsc#SLE-9518)

  - FIPS: Fixed a cfb8 decryption issue, no longer truncate
    output IV if input is shorter than block size.
    (bsc#1166881)

  - FIPS: Added Diffie Hellman public key verification test.
    (bsc#1155327)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168345"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gmp / gnutls / libnettle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11501");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gmp-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnutls-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmp10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmp10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmp10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmp10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmpxx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmpxx4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmpxx4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmpxx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-dane0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutls30-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");
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

if ( rpm_check(release:"SUSE15.1", reference:"gmp-debugsource-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gmp-devel-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-debugsource-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-guile-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gnutls-guile-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgmp10-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgmp10-debuginfo-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgmpxx4-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgmpxx4-debuginfo-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane-devel-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane0-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-dane0-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls-devel-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls30-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls30-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutls30-hmac-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx-devel-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx28-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgnutlsxx28-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libhogweed4-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libhogweed4-debuginfo-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnettle-debugsource-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnettle-devel-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnettle6-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnettle6-debuginfo-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nettle-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nettle-debuginfo-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"gmp-devel-32bit-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgmp10-32bit-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgmp10-32bit-debuginfo-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgmpxx4-32bit-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgmpxx4-32bit-debuginfo-6.1.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls-devel-32bit-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgnutls30-hmac-32bit-3.6.7-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-lp151.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-lp151.2.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gmp-debugsource / gmp-devel / libgmp10 / libgmp10-debuginfo / etc");
}
