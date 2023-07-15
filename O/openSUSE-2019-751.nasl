#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-751.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123322);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-0732");

  script_name(english:"openSUSE Security Update : openssl-1_1 (openSUSE-2019-751)");
  script_summary(english:"Check for the openSUSE-2019-751 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl-1_1 to 1.1.0i fixes the following issues :

These security issues were fixed :

  - CVE-2018-0732: During key agreement in a TLS handshake
    using a DH(E) based ciphersuite a malicious server could
    have sent a very large prime value to the client. This
    caused the client to spend an unreasonably long period
    of time generating a key for this prime resulting in a
    hang until the client has finished. This could be
    exploited in a Denial Of Service attack (bsc#1097158)

  - Make problematic ECDSA sign addition length-invariant

  - Add blinding to ECDSA and DSA signatures to protect
    against side channel attacks

These non-security issues were fixed :

  - When unlocking a pass phrase protected PEM file or
    PKCS#8 container, we now allow empty (zero character)
    pass phrases.

  - Certificate time validation (X509_cmp_time) enforces
    stricter compliance with RFC 5280. Fractional seconds
    and timezone offsets are no longer allowed.

  - Fixed a text canonicalisation bug in CMS

  - Add openssl(cli) Provide so the packages that require
    the openssl binary can require this instead of the new
    openssl meta package (bsc#1101470)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101470"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl-1_1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libopenssl-1_1-devel-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl-devel-1.1.0i-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-debuginfo-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-hmac-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1.1.0i-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-debuginfo-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-debugsource-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenssl-1_1-devel-32bit-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenssl1_1-32bit-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenssl1_1-32bit-debuginfo-1.1.0i-lp150.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libopenssl1_1-hmac-32bit-1.1.0i-lp150.3.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-1_1-devel / libopenssl-1_1-devel-32bit / libopenssl1_1 / etc");
}
