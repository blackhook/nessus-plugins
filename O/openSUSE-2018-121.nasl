#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-121.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106551);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5684");

  script_name(english:"openSUSE Security Update : freeimage (openSUSE-2018-121)");
  script_summary(english:"Check for the openSUSE-2018-121 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeimage fixes one issues.

This security issue was fixed :

  - CVE-2016-5684: Prevent out-of-bounds write vulnerability
    in the XMP image handling functionality. A specially
    crafted XMP file could have caused an arbitrary memory
    overwrite resulting in code execution (boo#1002621)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeimage packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeimage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeimage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreeimage3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreeimage3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreeimageplus3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreeimageplus3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"freeimage-debugsource-3.17.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeimage-devel-3.17.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreeimage3-3.17.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreeimage3-debuginfo-3.17.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreeimageplus3-3.17.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreeimageplus3-debuginfo-3.17.0-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeimage-debugsource / freeimage-devel / libfreeimage3 / etc");
}
