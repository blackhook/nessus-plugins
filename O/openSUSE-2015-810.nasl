#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-810.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87083);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8023");

  script_name(english:"openSUSE Security Update : strongswan (openSUSE-2015-810)");
  script_summary(english:"Check for the openSUSE-2015-810 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The strongswan package was updated to fix the following security 
issue :

  - CVE-2015-8023: Fixed an authentication bypass
    vulnerability in the eap-mschapv2 plugin (bsc#953817)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953817"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected strongswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-ipsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-libs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-nm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:strongswan-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"strongswan-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-debugsource-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-ipsec-debuginfo-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-libs0-debuginfo-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-mysql-debuginfo-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-nm-debuginfo-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"strongswan-sqlite-debuginfo-5.1.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-debugsource-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-ipsec-debuginfo-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-libs0-debuginfo-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-mysql-debuginfo-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-nm-debuginfo-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"strongswan-sqlite-debuginfo-5.1.3-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-debugsource-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-hmac-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-ipsec-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-ipsec-debuginfo-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-libs0-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-libs0-debuginfo-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-mysql-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-mysql-debuginfo-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-nm-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-nm-debuginfo-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-sqlite-5.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"strongswan-sqlite-debuginfo-5.2.2-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan / strongswan-debugsource / strongswan-ipsec / etc");
}
