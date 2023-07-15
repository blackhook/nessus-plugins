#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2628.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131689);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2019-13178");

  script_name(english:"openSUSE Security Update : calamares (openSUSE-2019-2628)");
  script_summary(english:"Check for the openSUSE-2019-2628 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for calamares fixes the following issues :

  - Launch with 'pkexec calamares' in openSUSE Tumbleweed,
    but launch with 'xdg-su -c calamares' in openSUSE Leap
    15.

Update to Calamares 3.2.15 :

  - 'displaymanager' module now treats 'sysconfig' as a
    regular entry in the 'displaymanagers' list, and the
    'sysconfigSetup' key is used as a shorthand to force
    only that entry in the list.

  - 'machineid' module has been re-written in C++ and
    extended with a new configuration key to generate
    urandom pool data.

  - 'unpackfs' now supports a special 'sourcefs' value of
    file for copying single files (optionally with renaming)
    or directory trees to the target system.

  - 'unpackfs' now support an 'exclude' and 'excludeFile'
    setting for excluding particular files or patters from
    unpacking.

Update to Calamares 3.2.14 :

  - 'locale' module no longer recognizes the legacy GeoIP
    configuration. This has been deprecated since Calamares
    3.2.8 and is now removed.

  - 'packagechooser' module can now be custom-labeled in the
    overall progress (left-hand column).

  - 'displaymanager' module now recognizes KDE Plasma 5.17.

  - 'displaymanager' module now can handle Wayland sessions
    and can detect sessions from their .desktop files.

  - 'unpackfs' now has special handling for sourcefs setting
    &ldquo;file&rdquo;. 

Update to Calamares 3.2.13.

More about upstream changes :

https://calamares.io/calamares-3.2.13-is-out/ and
https://calamares.io/calamares-3.2.12-is-out/

Update to Calamares 3.2.11 :

  - Fix race condition in modules/luksbootkeyfile/main.py
    (boo#1140256, CVE-2019-13178)

  - more about upstream changes in 3.2 versions can be found
    in https://calamares.io/ and
    https://github.com/calamares/calamares/releases"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://calamares.io/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://calamares.io/calamares-3.2.12-is-out/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://calamares.io/calamares-3.2.13-is-out/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/calamares/calamares/releases"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected calamares packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares-webview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:calamares-webview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"calamares-3.2.15-lp151.4.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"calamares-branding-upstream-3.2.15-lp151.4.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"calamares-debuginfo-3.2.15-lp151.4.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"calamares-debugsource-3.2.15-lp151.4.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"calamares-webview-3.2.15-lp151.4.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"calamares-webview-debuginfo-3.2.15-lp151.4.3.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "calamares / calamares-branding-upstream / calamares-debuginfo / etc");
}
