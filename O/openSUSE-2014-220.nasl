#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-220.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75298);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0004");

  script_name(english:"openSUSE Security Update : udisks2 (openSUSE-SU-2014:0388-1)");
  script_summary(english:"Check for the openSUSE-2014-220 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"udisks2 was updated to fix a buffer overflow in mount path parsing. If
users have the possibility to create very long mount points, such as
with FUSE, they could cause udisksd to crash, or even to run arbitrary
code as root with specially crafted mount paths. (bnc#865854,
CVE-2014-0004)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-03/msg00051.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected udisks2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudisks2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudisks2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-UDisks-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udisks2-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libudisks2-0-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudisks2-0-debuginfo-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-UDisks-2_0-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udisks2-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udisks2-debuginfo-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udisks2-debugsource-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udisks2-devel-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udisks2-lang-2.0.0-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libudisks2-0-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libudisks2-0-debuginfo-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"typelib-1_0-UDisks-2_0-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"udisks2-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"udisks2-debuginfo-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"udisks2-debugsource-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"udisks2-devel-2.1.1-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"udisks2-lang-2.1.1-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "udisks2");
}
