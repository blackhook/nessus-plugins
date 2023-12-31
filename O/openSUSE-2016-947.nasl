#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-947.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92777);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6504", "CVE-2016-6505", "CVE-2016-6506", "CVE-2016-6507", "CVE-2016-6508", "CVE-2016-6509", "CVE-2016-6510", "CVE-2016-6511");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2016-947)");
  script_summary(english:"Check for the openSUSE-2016-947 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wireshark was updated to 1.12.13 to fix a number of minor security
issues and bugs.

This release fixes a number issues in protocol dissectors that could
have allowed a remote attacker to crash Wireshark or cause excessive
CPU usage through specially crafted packages inserted into the network
or a capture file.

  - CVE-2016-6504: NDS dissector crash (boo#991012)

  - CVE-2016-6505: PacketBB crash (boo#991013)

  - CVE-2016-6506: WSP infinite loop (boo#991015)

  - CVE-2016-6507: MMSE infinite loop (boo#991016)

  - CVE-2016-6508: RLC long loop (boo#991017)

  - CVE-2016-6509: LDSS dissector crash (boo#991018)

  - CVE-2016-6510: RLC dissector crash (boo#991019)

  - CVE-2016-6511: OpenFlow long loop (boo#991020)

This update also includes further bug fixes and updated protocol
support as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-1.12.13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.13.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"wireshark-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debuginfo-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-debugsource-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-devel-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-gtk-debuginfo-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"wireshark-ui-qt-debuginfo-1.12.13-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debuginfo-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-debugsource-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-devel-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-gtk-debuginfo-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-1.12.13-29.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"wireshark-ui-qt-debuginfo-1.12.13-29.1") ) flag++;

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
