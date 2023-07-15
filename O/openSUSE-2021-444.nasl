#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-444.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147930);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2019-16091", "CVE-2019-16092", "CVE-2019-16093", "CVE-2019-16094", "CVE-2019-16095", "CVE-2019-20016", "CVE-2019-20063", "CVE-2020-36148", "CVE-2020-36149", "CVE-2020-36150", "CVE-2020-36151", "CVE-2020-36152", "CVE-2020-6860");

  script_name(english:"openSUSE Security Update : libmysofa (openSUSE-2021-444)");
  script_summary(english:"Check for the openSUSE-2021-444 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libmysofa fixes the following issues :

  - Added security backports: gh#hoene/libmysofa#136 -
    CVE-2020-36152 - boo#1181977 gh#hoene/libmysofa#138 -
    CVE-2020-36148 - boo#1181981 gh#hoene/libmysofa#137 -
    CVE-2020-36149 - boo#1181980 gh#hoene/libmysofa#134 -
    CVE-2020-36151 - boo#1181978 gh#hoene/libmysofa#135 -
    CVE-2020-36150 - boo#1181979 gh#hoene/libmysofa#96 -
    CVE-2020-6860 - boo#1182883

Update to version 0.9.1

  - Extended angular neighbor search to 'close the sphere'

  - Added and exposed mysofa_getfilter_float_nointerp method

  - Fixed various security issues CVE-2019-16091 -
    boo#1149919 CVE-2019-16092 - boo#1149920 CVE-2019-16093
    - boo#1149922 CVE-2019-16094 - boo#1149924
    CVE-2019-16095 - boo#1149926 CVE-2019-20016 -
    boo#1159839 CVE-2019-20063 - boo#1160040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182883"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libmysofa packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysofa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysofa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysofa0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysofa0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libmysofa-debugsource-0.9.1-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmysofa-devel-0.9.1-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmysofa0-0.9.1-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libmysofa0-debuginfo-0.9.1-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysofa-debugsource / libmysofa-devel / libmysofa0 / etc");
}
