#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-908.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87447);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");

  script_name(english:"openSUSE Security Update : OpenSSL (openSUSE-2015-908)");
  script_summary(english:"Check for the openSUSE-2015-908 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL was updated to fix three security issues.

The following vulnerabilities were fixed :

  - CVE-2015-3194: Certificate verify crash with missing PSS
    parameter (bsc#957815)

  - CVE-2015-3195: X509_ATTRIBUTE memory leak (bsc#957812)

  - CVE-2015-3196: Race condition handling PSK identify hint
    (bsc#957813)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenSSL packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libopenssl-devel-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libopenssl1_0_0-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libopenssl1_0_0-debuginfo-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-debuginfo-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openssl-debugsource-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1k-11.75.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl-devel-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-debuginfo-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libopenssl1_0_0-hmac-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-debuginfo-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"openssl-debugsource-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1k-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.1k-2.27.1") ) flag++;

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
