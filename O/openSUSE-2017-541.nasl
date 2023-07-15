#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-541.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100019);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5068");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2017-541)");
  script_summary(english:"Check for the openSUSE-2017-541 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to Chromium 58.0.3029.96 fixes one security issue :

  - CVE-2017-5068: race condition in WebRTC (bsc#1037594)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037594"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/08");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-58.0.3029.96-114.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-58.0.3029.96-114.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-58.0.3029.96-114.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-58.0.3029.96-114.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-58.0.3029.96-114.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-58.0.3029.96-104.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromedriver-debuginfo-58.0.3029.96-104.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-58.0.3029.96-104.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debuginfo-58.0.3029.96-104.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"chromium-debugsource-58.0.3029.96-104.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
