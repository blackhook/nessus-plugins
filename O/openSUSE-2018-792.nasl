#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-792.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111542);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-7325");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2018-792)");
  script_summary(english:"Check for the openSUSE-2018-792 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark fixes the following issues :

Security issues fixed :

  - CVE-2018-7325: RPKI-Router infinite loop (boo#1082692)

  - CVE-2018-14342: BGP dissector large loop
    (wnpa-sec-2018-34, boo#1101777)

  - CVE-2018-14344: ISMP dissector crash (wnpa-sec-2018-35,
    boo#1101788)

  - CVE-2018-14340: Multiple dissectors could crash
    (wnpa-sec-2018-36, boo#1101804)

  - CVE-2018-14343: ASN.1 BER dissector crash
    (wnpa-sec-2018-37, boo#1101786)

  - CVE-2018-14339: MMSE dissector infinite loop
    (wnpa-sec-2018-38, boo#1101810)

  - CVE-2018-14341: DICOM dissector crash (wnpa-sec-2018-39,
    boo#1101776)

  - CVE-2018-14368: Bazaar dissector infinite loop
    (wnpa-sec-2018-40, boo#1101794)

  - CVE-2018-14369: HTTP2 dissector crash (wnpa-sec-2018-41,
    boo#1101800)

Bug fixes :

  - Further bug fixes and updated protocol support as listed
    in:
    https://www.wireshark.org/docs/relnotes/wireshark-2.2.16
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.16.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/06");
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

if ( rpm_check(release:"SUSE42.3", reference:"wireshark-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debuginfo-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-debugsource-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-devel-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-gtk-debuginfo-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-2.2.16-44.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"wireshark-ui-qt-debuginfo-2.2.16-44.1") ) flag++;

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
