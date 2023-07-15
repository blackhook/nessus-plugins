#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-328.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108783);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-5729", "CVE-2018-5730");

  script_name(english:"openSUSE Security Update : krb5 (openSUSE-2018-328)");
  script_summary(english:"Check for the openSUSE-2018-328 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for krb5 provides the following fixes :

Security issues fixed :

  - CVE-2018-5730: DN container check bypass by supplying
    special crafted data (bsc#1083927).

  - CVE-2018-5729: NULL pointer dereference in kadmind or DN
    container check bypass by supplying special crafted data
    (bsc#1083926).

Non-security issues fixed :

  - Make it possible for legacy applications (e.g. SAP
    Netweaver) to remain compatible with newer Kerberos.
    System administrators who are experiencing this kind of
    compatibility issues may set the environment variable
    GSSAPI_ASSUME_MECH_MATCH to a non-empty value, and make
    sure the environment variable is visible and effective
    to the application startup script. (bsc#1057662)

  - Fix a GSS failure in legacy applications by not
    indicating deprecated GSS mechanisms in
    gss_indicate_mech() list. (bsc#1081725)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083927"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-otp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/02");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"krb5-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-client-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-client-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-debugsource-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-devel-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-mini-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-mini-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-mini-debugsource-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-mini-devel-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-kdb-ldap-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-preauth-otp-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-preauth-pkinit-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-server-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"krb5-server-debuginfo-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"krb5-32bit-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"krb5-devel-32bit-1.12.5-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-mini / krb5-mini-debuginfo / krb5-mini-debugsource / etc");
}