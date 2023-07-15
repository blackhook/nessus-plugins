#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-79.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133132);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2018-1088", "CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10924", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930", "CVE-2018-1112");

  script_name(english:"openSUSE Security Update : glusterfs (openSUSE-2020-79)");
  script_summary(english:"Check for the openSUSE-2020-79 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glusterfs fixes the following issues :

glusterfs was update to release 3.12.15 :

  - Fixed a number of bugs and security issues :

  - CVE-2018-1088, CVE-2018-1112 [boo#1090084],
    CVE-2018-10904 [boo#1107018], CVE-2018-10907
    [boo#1107019], CVE-2018-10911 [boo#1107020],
    CVE-2018-10913 [boo#1107021], CVE-2018-10914
    [boo#1107022], CVE-2018-10923 [boo#1107023],
    CVE-2018-10924 [boo#1107024], CVE-2018-10926
    [boo#1107025], CVE-2018-10927 [boo#1107026],
    CVE-2018-10928 [boo#1107027], CVE-2018-10928
    [boo#1107027], CVE-2018-10929 [boo#1107028],
    CVE-2018-10930 [boo#1107029], boo#1105776 ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107029"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glusterfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfchangelog0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfchangelog0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfrpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfrpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfxdr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgfxdr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglusterfs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglusterfs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"glusterfs-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"glusterfs-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"glusterfs-debugsource-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"glusterfs-devel-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfapi0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfapi0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfchangelog0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfchangelog0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfdb0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfdb0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfrpc0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfrpc0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfxdr0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgfxdr0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libglusterfs0-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libglusterfs0-debuginfo-3.12.15-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-gluster-3.12.15-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-debuginfo / glusterfs-debugsource / etc");
}
