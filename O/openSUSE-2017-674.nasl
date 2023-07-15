#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-674.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100752);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9343", "CVE-2017-9344", "CVE-2017-9345", "CVE-2017-9346", "CVE-2017-9347", "CVE-2017-9348", "CVE-2017-9349", "CVE-2017-9350", "CVE-2017-9351", "CVE-2017-9352", "CVE-2017-9353", "CVE-2017-9354");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2017-674)");
  script_summary(english:"Check for the openSUSE-2017-674 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark fixes minor vulnerabilities that could be
used to trigger dissector crashes, infinite loops, or cause excessive
use of CPU resources by making Wireshark read specially crafted
packages from the network or a capture file :

  - CVE-2017-9352: Bazaar dissector infinite loop
    (boo#1042304)

  - CVE-2017-9348: DOF dissector read overflow (boo#1042303)

  - CVE-2017-9351: DHCP dissector read overflow
    (boo#1042302)

  - CVE-2017-9346: SoulSeek dissector infinite loop
    (boo#1042301)

  - CVE-2017-9345: DNS dissector infinite loop (boo#1042300)

  - CVE-2017-9349: DICOM dissector infinite loop
    (boo#1042305)

  - CVE-2017-9350: openSAFETY dissector memory exhaustion
    (boo#1042299)

  - CVE-2017-9344: BT L2CAP dissector divide by zero
    (boo#1042298)

  - CVE-2017-9343: MSNIP dissector crash (boo#1042309)

  - CVE-2017-9347: ROS dissector crash (boo#1042308)

  - CVE-2017-9354: RGMP dissector crash (boo#1042307)

  - CVE-2017-9353: IPv6 dissector crash (boo#1042306)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"wireshark-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debuginfo-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-debugsource-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-devel-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-gtk-debuginfo-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-2.2.7-14.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"wireshark-ui-qt-debuginfo-2.2.7-14.6.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-debugsource / etc");
}
