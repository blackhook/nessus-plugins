#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/03/23. Deprecated by openSUSE-2016-664.nasl.

include("compat.inc");

if (description)
{
  script_id(89721);
  script_version("2.6");
  script_cvs_date("Date: 2018/07/20  0:18:55");

  script_cve_id("CVE-2015-8126", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642");

  script_name(english:"openSUSE Security Update : 4789 (4789-1) (deprecated)");
  script_summary(english:"Check for the 4789-1 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 49.0.2623.75 to fix the following security
issues: (boo#969333)

  - CVE-2016-1630: Same-origin bypass in Blink

  - CVE-2016-1631: Same-origin bypass in Pepper Plugin

  - CVE-2016-1632: Bad cast in Extensions

  - CVE-2016-1633: Use-after-free in Blink

  - CVE-2016-1634: Use-after-free in Blink

  - CVE-2016-1635: Use-after-free in Blink

  - CVE-2016-1636: SRI Validation Bypass

  - CVE-2015-8126: Out-of-bounds access in libpng

  - CVE-2016-1637: Information Leak in Skia

  - CVE-2016-1638: WebAPI Bypass

  - CVE-2016-1639: Use-after-free in WebRTC

  - CVE-2016-1640: Origin confusion in Extensions UI

  - CVE-2016-1641: Use-after-free in Favicon

  - CVE-2016-1642: Various fixes from internal audits,
    fuzzing and other initiatives

  - Multiple vulnerabilities in V8 fixed at the tip of the
    4.9 branch (currently 4.9.385.26)

This plugin has been renamed to openSUSE-2016-664.nasl, plugin ID
90107."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969333"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use openSUSE-2016-664.nasl (plugin ID 90107) instead.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-49.0.2623.75-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-49.0.2623.75-27.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
