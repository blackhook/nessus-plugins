#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-408.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147794);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/05");

  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230", "CVE-2021-27212");
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"openSUSE Security Update : openldap2 (openSUSE-2021-408)");
  script_summary(english:"Check for the openSUSE-2021-408 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openldap2 fixes the following issues :

  - bsc#1182408 CVE-2020-36230 - an assertion failure in
    slapd in the X.509 DN parsing in decode.c
    ber_next_element, resulting in denial of service.

  - bsc#1182411 CVE-2020-36229 - ldap_X509dn2bv crash in the
    X.509 DN parsing in ad_keystring, resulting in denial of
    service.

  - bsc#1182412 CVE-2020-36228 - integer underflow leading
    to crash in the Certificate List Exact Assertion
    processing, resulting in denial of service.

  - bsc#1182413 CVE-2020-36227 - infinite loop in slapd with
    the cancel_extop Cancel operation, resulting in denial
    of service.

  - bsc#1182416 CVE-2020-36225 - double free and slapd crash
    in the saslAuthzTo processing, resulting in denial of
    service.

  - bsc#1182417 CVE-2020-36224 - invalid pointer free and
    slapd crash in the saslAuthzTo processing, resulting in
    denial of service.

  - bsc#1182415 CVE-2020-36226 - memch->bv_len
    miscalculation and slapd crash in the saslAuthzTo
    processing, resulting in denial of service.

  - bsc#1182419 CVE-2020-36222 - assertion failure in slapd
    in the saslAuthzTo validation, resulting in denial of
    service.

  - bsc#1182420 CVE-2020-36221 - slapd crashes in the
    Certificate Exact Assertion processing, resulting in
    denial of service (schema_init.c
    serialNumberAndIssuerCheck).

  - bsc#1182418 CVE-2020-36223 - slapd crash in the Values
    Return Filter control handling, resulting in denial of
    service (double free and out-of-bounds read).

  - bsc#1182279 CVE-2021-27212 - an assertion failure in
    slapd can occur in the issuerAndThisUpdateCheck function
    via a crafted packet, resulting in a denial of service
    (daemon exit) via a short timestamp. This is related to
    schema_init.c and checkTime.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182420"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openldap2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-ppolicy-check-password");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-ppolicy-check-password-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libldap-2_4-2-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldap-2_4-2-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldap-data-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-meta-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-meta-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-perl-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-perl-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sock-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sock-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sql-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sql-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-client-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-client-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-contrib-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-contrib-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-debugsource-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-devel-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-devel-static-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-ppolicy-check-password-1.2-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-debuginfo-2.4.46-lp152.14.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.46-lp152.14.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libldap-2_4-2 / libldap-2_4-2-debuginfo / libldap-data / openldap2 / etc");
}
