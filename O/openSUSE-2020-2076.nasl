#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2076.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143312);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/02");

  script_cve_id("CVE-2020-26575", "CVE-2020-28030");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2020-2076)");
  script_summary(english:"Check for the openSUSE-2020-2076 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for wireshark fixes the following issues :

  - wireshark was updated to 3.2.8 :

  - CVE-2020-26575: Fixed an issue where FBZERO dissector
    was entering in infinite loop (bsc#1177406)

  - CVE-2020-28030: Fixed an issue where GQUIC dissector was
    crashing (bsc#1178291)

  - Infinite memory allocation while parsing this tcp packet

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178291"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"libwireshark13-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwireshark13-debuginfo-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwiretap10-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwiretap10-debuginfo-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwsutil11-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libwsutil11-debuginfo-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-debuginfo-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-debugsource-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-devel-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-ui-qt-3.2.8-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-ui-qt-debuginfo-3.2.8-lp152.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwireshark13 / libwireshark13-debuginfo / libwiretap10 / etc");
}
