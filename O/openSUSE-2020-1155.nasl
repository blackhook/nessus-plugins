#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1155.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139444);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/28");

  script_cve_id(
    "CVE-2020-15652",
    "CVE-2020-15653",
    "CVE-2020-15654",
    "CVE-2020-15655",
    "CVE-2020-15656",
    "CVE-2020-15657",
    "CVE-2020-15658",
    "CVE-2020-15659",
    "CVE-2020-6463",
    "CVE-2020-6514"
  );
  script_xref(name:"IAVA", value:"2020-A-0344-S");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2020-1155)");
  script_summary(english:"Check for the openSUSE-2020-1155 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

  - Firefox Extended Support Release 78.1.0 ESR

  - Fixed: Various stability, functionality, and security
    fixes (bsc#1174538)

  - CVE-2020-15652: Potential leak of redirect targets when
    loading scripts in a worker

  - CVE-2020-6514: WebRTC data channel leaks internal
    address to peer

  - CVE-2020-15655: Extension APIs could be used to bypass
    Same-Origin Policy

  - CVE-2020-15653: Bypassing iframe sandbox when allowing
    popups

  - CVE-2020-6463: Use-after-free in ANGLE
    gl::Texture::onUnbindAsSamplerTexture

  - CVE-2020-15656: Type confusion for special arguments in
    IonMonkey

  - CVE-2020-15658: Overriding file type when saving to disk

  - CVE-2020-15657: DLL hijacking due to incorrect loading
    path

  - CVE-2020-15654: Custom cursor can overlay user interface

  - CVE-2020-15659: Memory safety bugs fixed in Firefox 79
    and Firefox ESR 78.1

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174538");
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15656");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-branding-upstream-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-buildsymbols-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debuginfo-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-debugsource-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-devel-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-common-78.1.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"MozillaFirefox-translations-other-78.1.0-lp152.2.12.1") ) flag++;

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
