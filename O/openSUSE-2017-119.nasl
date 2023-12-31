#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-119.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96645);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5219");

  script_name(english:"openSUSE Security Update : v8 (openSUSE-2017-119)");
  script_summary(english:"Check for the openSUSE-2017-119 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for v8 fixes the following issues :

  - maliciously crafted java script code could cause v8 in
    chromium to crash"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013274"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected v8 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libv8-5-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libv8-5-debuginfo-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"v8-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"v8-debuginfo-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"v8-debugsource-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"v8-devel-5.3.332-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"v8-private-headers-devel-5.3.332-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libv8-5 / libv8-5-debuginfo / v8 / v8-debuginfo / v8-debugsource / etc");
}
