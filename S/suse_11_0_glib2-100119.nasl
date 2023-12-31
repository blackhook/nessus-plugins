#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update glib2-1822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46007);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3289");

  script_name(english:"openSUSE Security Update : glib2 (openSUSE-SU-2010:0155-1)");
  script_summary(english:"Check for the glib2-1822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The when copying symbolic links the g_file_copy function set the
target of the link to mode 0777 therefore exposing potentially
sensitive information or allowing other user to modify files they
should not have access to (CVE-2009-3289)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=538005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-04/msg00082.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/27");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"glib2-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"glib2-branding-upstream-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"glib2-devel-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libgio-2_0-0-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libgio-fam-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libglib-2_0-0-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libgmodule-2_0-0-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libgobject-2_0-0-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libgthread-2_0-0-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.16.3-20.8") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.16.3-20.8") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2 / glib2-branding-upstream / glib2-devel / libgio-2_0-0 / etc");
}
