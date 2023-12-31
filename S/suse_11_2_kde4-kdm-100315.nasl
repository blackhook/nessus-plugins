#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kde4-kdm-2134.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45538);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0436");

  script_name(english:"openSUSE Security Update : kde4-kdm (openSUSE-SU-2010:0112-1)");
  script_summary(english:"Check for the kde4-kdm-2134 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KDE KDM contains a local race condition which allows to make
arbitrary files world-writable. CVE-2010-0436 has been assigned to
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-04/msg00013.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kde4-kdm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kde4-kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase4-workspace-ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdm-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kwin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"kde4-kgreeter-plugins-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdebase4-workspace-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdebase4-workspace-branding-upstream-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdebase4-workspace-devel-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdebase4-workspace-google-gadgets-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdebase4-workspace-ksysguardd-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdm-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kdm-branding-upstream-4.3.5-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kwin-4.3.5-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde4-kgreeter-plugins / kdebase4-workspace / etc");
}
