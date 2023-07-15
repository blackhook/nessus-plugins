#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1179.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104083);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : xerces-j2 (openSUSE-2017-1179)");
  script_summary(english:"Check for the openSUSE-2017-1179 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xerces-j2 was updated to fix several issues.

This security issue was fixed :

  - bsc#814241: Prevent possible DoS through very long
    attribute names

This non-security issue was fixed :

  - Prevent StackOverflowError when applying a pattern
    restriction on long strings while trying to validate an
    XML file against a schema (bsc#1047536, bsc#879138)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=814241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=879138"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xerces-j2-2.8.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xerces-j2-demo-2.8.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xerces-j2-scripts-2.8.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xerces-j2-xml-apis-2.8.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xerces-j2-xml-resolver-2.8.1-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xerces-j2-2.8.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xerces-j2-demo-2.8.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xerces-j2-scripts-2.8.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xerces-j2-xml-apis-2.8.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xerces-j2-xml-resolver-2.8.1-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-demo / xerces-j2-scripts / xerces-j2-xml-apis / etc");
}
