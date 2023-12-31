#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update glib2-815.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40222);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-4316");

  script_name(english:"openSUSE Security Update : glib2 (glib2-815)");
  script_summary(english:"Check for the glib2-815 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Large strings could lead to a heap overflow in the base64 encoding and
decoding functions. Attackers could potentially exploit that to
execute arbitrary code (CVE-2008-4316)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=449927"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glib2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-lang");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"glib2-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glib2-branding-upstream-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glib2-devel-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"glib2-lang-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgio-2_0-0-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgio-fam-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libglib-2_0-0-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgmodule-2_0-0-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgobject-2_0-0-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgthread-2_0-0-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.18.2-5.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.18.2-5.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2 / glib2-branding-upstream / glib2-devel / glib2-lang / etc");
}
