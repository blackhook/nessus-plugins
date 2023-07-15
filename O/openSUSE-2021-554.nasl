#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-554.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(148696);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2021-3472");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-2021-554)");
  script_summary(english:"Check for the openSUSE-2021-554 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for xorg-x11-server fixes the following issues :

  - CVE-2021-3472: XChangeFeedbackControl Integer Underflow
    Privilege Escalation (bsc#1180128)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180128"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3472");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-wayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");
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

if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-debuginfo-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-debugsource-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-extra-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-extra-debuginfo-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-sdk-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-source-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-wayland-1.20.3-lp152.8.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xorg-x11-server-wayland-debuginfo-1.20.3-lp152.8.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server / xorg-x11-server-debuginfo / etc");
}
