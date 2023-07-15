#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-577.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149627);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-22879");

  script_name(english:"openSUSE Security Update : nextcloud-desktop (openSUSE-2021-577)");
  script_summary(english:"Check for the openSUSE-2021-577 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nextcloud-desktop fixes the following issues :

nextcloud-desktop was updated to 3.1.3 :

  - desktop#2884 [stable-3.1] Add support for Hirsute

  - desktop#2920 [stable-3.1] Validate sensitive URLs to
    onle allow http(s) schemes.

  - desktop#2926 [stable-3.1] Validate the providers ssl
    certificate

  - desktop#2939 Bump release to 3.1.3

This also fix security issues :

  - (boo#1184770, CVE-2021-22879, NC-SA-2021-008 , CWE-99)

    Nextcloud Desktop Client prior to 3.1.3 is vulnerable to
    resource injection by way of missing validation of URLs,
    allowing a malicious server to execute remote commands.
    User interaction is needed for exploitation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184770"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nextcloud-desktop packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caja-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnextcloudsync-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnextcloudsync0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnextcloudsync0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nemo-extension-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-dolphin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-dolphin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud-desktop-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"caja-extension-nextcloud-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnextcloudsync-devel-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnextcloudsync0-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnextcloudsync0-debuginfo-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nautilus-extension-nextcloud-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nemo-extension-nextcloud-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-debuginfo-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-debugsource-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-dolphin-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-dolphin-debuginfo-3.1.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nextcloud-desktop-lang-3.1.3-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "caja-extension-nextcloud / libnextcloudsync-devel / etc");
}
