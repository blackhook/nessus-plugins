#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1176.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104080);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-7837", "CVE-2017-1000250");

  script_name(english:"openSUSE Security Update : bluez (openSUSE-2017-1176) (BlueBorne)");
  script_summary(english:"Check for the openSUSE-2017-1176 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bluez fixes the following vulnerabilities :

  - CVE-2016-7837: Buffer overflow in parse_line function
    (bsc#1026652)

  - CVE-2017-1000250: information disclosure vulnerability
    in service_search_attr_req (bsc#1057342)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057342"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bluez packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bluez-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbluetooth3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbluetooth3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbluetooth3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbluetooth3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
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

if ( rpm_check(release:"SUSE42.2", reference:"bluez-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-cups-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-cups-debuginfo-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-debuginfo-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-debugsource-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-devel-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-test-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bluez-test-debuginfo-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libbluetooth3-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libbluetooth3-debuginfo-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"bluez-devel-32bit-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libbluetooth3-32bit-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libbluetooth3-debuginfo-32bit-5.41-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-cups-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-cups-debuginfo-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-debuginfo-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-debugsource-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-devel-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-test-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bluez-test-debuginfo-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libbluetooth3-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libbluetooth3-debuginfo-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"bluez-devel-32bit-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libbluetooth3-32bit-5.41-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libbluetooth3-debuginfo-32bit-5.41-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez / bluez-cups / bluez-cups-debuginfo / bluez-debuginfo / etc");
}
