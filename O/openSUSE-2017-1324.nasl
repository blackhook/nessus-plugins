#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1324.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105224);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3735", "CVE-2017-3736");

  script_name(english:"openSUSE Security Update : openssl (openSUSE-2017-1324)");
  script_summary(english:"Check for the openSUSE-2017-1324 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes the following issues :

Security issues fixed :

  - CVE-2017-3735: openssl1,openssl: Malformed X.509
    IPAdressFamily could cause OOB read (bsc#1056058)

  - CVE-2017-3736: openssl: bn_sqrx8x_internal carry bug on
    x86_64 (bsc#1066242)

  - Out of bounds read+crash in DES_fcrypt (bsc#1065363)

  - openssl DEFAULT_SUSE cipher list is missing ECDHE-ECDSA
    ciphers (bsc#1055825)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066242"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libopenssl-devel-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libopenssl1_0_0-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libopenssl1_0_0-debuginfo-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libopenssl1_0_0-hmac-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssl-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssl-cavs-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssl-cavs-debuginfo-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssl-debuginfo-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openssl-debugsource-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenssl-devel-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenssl1_0_0-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenssl1_0_0-debuginfo-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenssl1_0_0-hmac-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-cavs-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-cavs-debuginfo-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-debuginfo-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssl-debugsource-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-devel / libopenssl-devel-32bit / libopenssl1_0_0 / etc");
}
