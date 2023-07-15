#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1163.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104076);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13087", "CVE-2017-13088");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"openSUSE Security Update : wpa_supplicant (openSUSE-2017-1163) (KRACK)");
  script_summary(english:"Check for the openSUSE-2017-1163 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wpa_supplicant fixes the security issues :

  - Several vulnerabilities in standard conforming
    implementations of the WPA2 protocol have been
    discovered and published under the code name KRACK. This
    update remedies those issues in a backwards compatible
    manner, i.e. the updated wpa_supplicant can interface
    properly with both vulnerable and patched
    implementations of WPA2, but an attacker won't be able
    to exploit the KRACK weaknesses in those connections
    anymore even if the other party is still vulnerable.
    [bsc#1056061, CVE-2017-13078, CVE-2017-13079,
    CVE-2017-13080, CVE-2017-13081, CVE-2017-13087,
    CVE-2017-13088]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056061"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wpa_supplicant packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if ( rpm_check(release:"SUSE42.2", reference:"wpa_supplicant-2.2-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wpa_supplicant-debuginfo-2.2-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wpa_supplicant-debugsource-2.2-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wpa_supplicant-gui-2.2-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wpa_supplicant-gui-debuginfo-2.2-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wpa_supplicant-2.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wpa_supplicant-debuginfo-2.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wpa_supplicant-debugsource-2.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wpa_supplicant-gui-2.2-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wpa_supplicant-gui-debuginfo-2.2-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant / wpa_supplicant-debuginfo / etc");
}
