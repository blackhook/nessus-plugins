#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-675.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100753);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6489");

  script_name(english:"openSUSE Security Update : libnettle (openSUSE-2017-675)");
  script_summary(english:"Check for the openSUSE-2017-675 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libnettle fixes the following issues :

  - CVE-2016-6489 :

  - Reject invalid RSA keys with even modulo.

  - Check for invalid keys, with even p, in dsa_sign().

  - Use function mpz_powm_sec() instead of mpz_powm()
    (bsc#991464).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991464"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnettle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/13");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libhogweed2-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libhogweed2-debuginfo-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnettle-debugsource-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnettle-devel-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnettle4-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libnettle4-debuginfo-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nettle-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nettle-debuginfo-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libhogweed2-32bit-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libhogweed2-debuginfo-32bit-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libnettle-devel-32bit-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libnettle4-32bit-2.7.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libnettle4-debuginfo-32bit-2.7.1-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libhogweed2 / libhogweed2-32bit / libhogweed2-debuginfo / etc");
}
