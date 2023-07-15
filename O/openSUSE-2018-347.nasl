#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-347.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108937);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-9256", "CVE-2018-9259", "CVE-2018-9260", "CVE-2018-9261", "CVE-2018-9262", "CVE-2018-9263", "CVE-2018-9264", "CVE-2018-9265", "CVE-2018-9266", "CVE-2018-9267", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9270", "CVE-2018-9271", "CVE-2018-9272", "CVE-2018-9273", "CVE-2018-9274");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2018-347)");
  script_summary(english:"Check for the openSUSE-2018-347 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark fixes the following issues :

Minor vulnerabilities that could be used to trigger dissector crashes
or cause dissectors to go into large infinite loops by making
Wireshark read specially crafted packages from the network or capture
files (boo#1088200) :

  - CVE-2018-9264: ADB dissector crash 

  - CVE-2018-9260: IEEE 802.15.4 dissector crash 

  - CVE-2018-9261: NBAP dissector crash 

  - CVE-2018-9262: VLAN dissector crash

  - CVE-2018-9256: LWAPP dissector crash

  - CVE-2018-9263: Kerberos dissector crash

  - CVE-2018-9259: MP4 dissector crash

  - Memory leaks in multiple dissectors: CVE-2018-9265,
    CVE-2018-9266, CVE-2018-9267, CVE-2018-9268,
    CVE-2018-9269, CVE-2018-9270, CVE-2018-9271,
    CVE-2018-9272, CVE-2018-9273, CVE-2018-9274

This update also contains all upstream bug fixes and updated protocol
support as listed in :

https://www.wireshark.org/docs/relnotes/wireshark-2.2.14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.14.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"wireshark-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debuginfo-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debugsource-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-devel-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-debuginfo-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-2.2.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-debuginfo-2.2.14-38.1") ) flag++;

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
