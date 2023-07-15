#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1632.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119953);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-20184", "CVE-2018-20189");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2018-1632)");
  script_summary(english:"Check for the openSUSE-2018-1632 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes the following issues :

Security issues fixed :

  - CVE-2018-20184: Fixed heap-based buffer overflow in the
    WriteTGAImage function of tga.c (bsc#1119822)

  - CVE-2018-20189: Fixed denial of service vulnerability in
    ReadDIBImage function of coders/dib.c (bsc#1119790)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119822"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debuginfo-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debugsource-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-devel-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-devel-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick3-config-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-1.3.25-120.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-debuginfo-1.3.25-120.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
