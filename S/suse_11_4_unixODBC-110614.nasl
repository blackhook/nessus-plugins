#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update unixODBC-4713.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76039);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-1145");

  script_name(english:"openSUSE Security Update : unixODBC (openSUSE-SU-2011:0655-1)");
  script_summary(english:"Check for the unixODBC-4713 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted reply of a malicious server could overflow a buffer
in unixODBC (CVE-2011-1145)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=678796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-06/msg00034.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unixODBC packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unixODBC-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"unixODBC-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"unixODBC-debuginfo-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"unixODBC-debugsource-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"unixODBC-devel-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"unixODBC-32bit-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"unixODBC-debuginfo-32bit-2.2.12-207.208.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"unixODBC-devel-32bit-2.2.12-207.208.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unixODBC / unixODBC-32bit / unixODBC-devel / unixODBC-devel-32bit / etc");
}
