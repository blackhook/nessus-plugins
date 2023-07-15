#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-210.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107001);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7419", "CVE-2018-7420", "CVE-2018-7421");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2018-210)");
  script_summary(english:"Check for the openSUSE-2018-210 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Wireshark to version 2.2.13 fixes a number of minor
vulnerabilities that could be used to trigger dissector crashes or
cause dissectors to go into large infinite loops by making Wireshark
read specially crafted packages from the network or capture files:
(boo#1082692) :

  - CVE-2018-7335: The IEEE 802.11 dissector could crash

  - CVE-2018-7321, CVE-2018-7322, CVE-2018-7323,
    CVE-2018-7324, CVE-2018-7325, CVE-2018-7326,
    CVE-2018-7327, CVE-2018-7328, CVE-2018-7329,
    CVE-2018-7330, CVE-2018-7331, CVE-2018-7332,
    CVE-2018-7333, CVE-2018-7421: Multiple dissectors could
    go into large infinite loops

  - CVE-2018-7334: The UMTS MAC dissector could crash

  - CVE-2018-7337: The DOCSIS dissector could crash

  - CVE-2018-7336: The FCP dissector could crash

  - CVE-2018-7320: The SIGCOMP dissector could crash

  - CVE-2018-7420: The pcapng file parser could crash

  - CVE-2018-7417: The IPMI dissector could crash

  - CVE-2018-7418: The SIGCOMP dissector could crash

  - CVE-2018-7419: The NBAP disssector could crash

This update also contains further bug fixes and updated protocol
support as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-2.2.13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"wireshark-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debuginfo-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debugsource-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-devel-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-debuginfo-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-2.2.13-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-debuginfo-2.2.13-35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
