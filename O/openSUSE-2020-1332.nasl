#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1332.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140367);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2020-15103");

  script_name(english:"openSUSE Security Update : freerdp (openSUSE-2020-1332)");
  script_summary(english:"Check for the openSUSE-2020-1332 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for freerdp fixes the following issues :

  - CVE-2020-15103: Fix integer overflow due to missing
    input sanitation in rdpegfx channel (bsc#1174321).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174321"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected freerdp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-wayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuwac0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwinpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwinpr2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uwac0-0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:winpr2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"freerdp-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-debugsource-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-devel-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-proxy-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-proxy-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-server-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-server-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-wayland-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-wayland-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreerdp2-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreerdp2-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libuwac0-0-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libuwac0-0-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwinpr2-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwinpr2-debuginfo-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"uwac0-0-devel-2.1.2-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"winpr2-devel-2.1.2-lp151.5.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-debugsource / freerdp-devel / etc");
}
