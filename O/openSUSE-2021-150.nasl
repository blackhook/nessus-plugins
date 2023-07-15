#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-150.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145273);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/27");

  script_cve_id("CVE-2020-29385");

  script_name(english:"openSUSE Security Update : gdk-pixbuf (openSUSE-2021-150)");
  script_summary(english:"Check for the openSUSE-2021-150 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for gdk-pixbuf fixes the following issues :

  - CVE-2020-29385: Fixed an infinite loop in lzw.c in the
    function write_indexes (bsc#1180393).

  - Fixed an integer underflow in the GIF loader
    (bsc#1174307).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180393"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-thumbnailer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GdkPixbuf-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GdkPixdata-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-debugsource-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-devel-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-devel-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-lang-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-query-loaders-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-query-loaders-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-thumbnailer-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-thumbnailer-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgdk_pixbuf-2_0-0-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GdkPixbuf-2_0-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-GdkPixdata-2_0-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-devel-32bit-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-devel-32bit-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-debuginfo-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-debuginfo-2.40.0-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-debugsource / gdk-pixbuf-devel / etc");
}
