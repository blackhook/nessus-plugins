#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-638.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79104);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8483");

  script_name(english:"openSUSE Security Update : quassel (openSUSE-SU-2014:1382-1)");
  script_summary(english:"Check for the openSUSE-2014-638 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"quassel was updated to fix an out-of-bound read (CVE-2014-8483)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-11/msg00028.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quassel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quassel-mono-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"quassel-base-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-client-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-client-debuginfo-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-core-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-core-debuginfo-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-debugsource-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-mono-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"quassel-mono-debuginfo-0.8.0-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-base-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-client-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-client-debuginfo-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-core-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-core-debuginfo-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-debugsource-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-mono-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"quassel-mono-debuginfo-0.9.2-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-base-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-client-debuginfo-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-core-debuginfo-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-debugsource-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-0.10.0-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"quassel-mono-debuginfo-0.10.0-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quassel");
}
