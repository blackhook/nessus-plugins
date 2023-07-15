#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-950.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112264);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12434");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2018-950)");
  script_summary(english:"Check for the openSUSE-2018-950 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libressl to version 2.8.0 fixes the following issues :

Security issues fixed :

  - CVE-2018-12434: Avoid a timing side-channel leak when
    generating DSA and ECDSA signatures. (boo#1097779)

  - Reject excessively large primes in DH key generation.

Other bugs fixed :

  - Fixed a pair of 20+ year-old bugs in
    X509_NAME_add_entry.

  - Tighten up checks for various X509_VERIFY_PARAM
    functions, 'poisoning' parameters so that an unverified
    certificate cannot be used if it fails verification.

  - Fixed a potential memory leak on failure in
    ASN1_item_digest.

  - Fixed a potential memory alignment crash in
    asn1_item_combine_free.

  - Removed unused SSL3_FLAGS_DELAY_CLIENT_FINISHED and
    SSL3_FLAGS_POP_BUFFER flags in write path, simplifying
    IO paths.

  - Removed SSL_OP_TLS_ROLLBACK_BUG buggy client
    workarounds.

  - Added const annotations to many existing APIs from
    OpenSSL, making interoperability easier for downstream
    applications.

  - Added a missing bounds check in c2i_ASN1_BIT_STRING.

  - Removed three remaining single DES cipher suites.

  - Fixed a potential leak/incorrect return value in DSA
    signature generation.

  - Added a blinding value when generating DSA and ECDSA
    signatures, in order to reduce the possibility of a
    side-channel attack leaking the private key.

  - Added ECC constant time scalar multiplication support.

  - Revised the implementation of RSASSA-PKCS1-v1_5 to match
    the specification in RFC 8017."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097779"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto43-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl45-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls17-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");
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

if ( rpm_check(release:"SUSE15.0", reference:"libcrypto43-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libcrypto43-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libressl-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libressl-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libressl-debugsource-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libressl-devel-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libssl45-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libssl45-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libtls17-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libtls17-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcrypto43-32bit-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libcrypto43-32bit-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libressl-devel-32bit-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libssl45-32bit-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libssl45-32bit-debuginfo-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libtls17-32bit-2.8.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libtls17-32bit-debuginfo-2.8.0-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto43 / libcrypto43-debuginfo / libressl / libressl-debuginfo / etc");
}
