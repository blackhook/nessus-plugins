#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1004.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123148);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12405", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498");

  script_name(english:"openSUSE Security Update : Mozilla Firefox (openSUSE-2019-1004)");
  script_summary(english:"Check for the openSUSE-2019-1004 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update to Mozilla Firefox 60.4.0 ESR fixes security issues and
bugs.

Security issues fixed as part of the MFSA 2018-30 advisory
(boo#1119105) :

  - CVE-2018-17466: Buffer overflow and out-of-bounds read
    in ANGLE library with TextureStorage11

  - CVE-2018-18492: Use-after-free with select element

  - CVE-2018-18493: Buffer overflow in accelerated 2D canvas
    with Skia

  - CVE-2018-18494: Same-origin policy violation using
    location attribute and performance.getEntries to steal
    cross-origin URLs

  - CVE-2018-18498: Integer overflow when calculating buffer
    sizes for images

  - CVE-2018-12405: Memory safety bugs fixed in Firefox 64
    and Firefox ESR 60.4

The following changes are included :

  - now requires NSS >= 3.36.6

  - Updated list of currency codes to include Unidad
    Previsional (UYW)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119105"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected Mozilla Firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-branding-upstream-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-buildsymbols-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debuginfo-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-debugsource-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-devel-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-common-60.4.0-lp150.3.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"MozillaFirefox-translations-other-60.4.0-lp150.3.30.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
