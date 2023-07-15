#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-767.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111419);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13054");

  script_name(english:"openSUSE Security Update : cinnamon (openSUSE-2018-767)");
  script_summary(english:"Check for the openSUSE-2018-767 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cinnamon fixes the following issues :

Security issue fixed :

  - CVE-2018-13054: Fix symlink attack vulnerability
    (boo#1083067).

Bug fixes :

  - Update to version 3.4.6 (changes since 3.4.4) :

  - osdWindow.js: Always check the theme node on first
    showing - an actor's width isn't necessarily filled if
    it hasn't been explicitly set, causing the first few
    activations of the OSD to not show an accurate level
    bar.

  - cs_default: Fix an incorrect button label (but preserve
    translations).

  - main.js: Remove an obsolete Meta enum member reference.

  - workspace.js: Use our normal prototype init method.

  - workspace.js: Initalise WindowClone._zoomStep to 0.

  - slideshow-applet: Fix a translation.

  - cs_themes.py: Create the file
    '~/.icons/default/index.theme' and set the selected
    cursor theme inside of it. This ensures other (non-gtk)
    applications end up using the same theme (though they
    are required to be restarted for these changes to take
    effect).

  - keyboard-applet: Applet icon vanishes when moved in edit
    mode.

  - cinnamon-json-makepot: Add keyword option, change
    language used by xgettext to JavaScript.

  - expoThumbnail: Correct a couple of calls with mismatched
    argument counts.

  - window-list: Set AppMenuButtons unreactive during panel
    edit mode.

  - panel-launchers: Set PanelAppLaunchers unreactive during
    panel edit mode.

  - windows-quick-list: Fix argument warning.

  - Fix a reference to undefined actor._delegate warning.

  - ui/environment: Handle undefined actors in
    containerClass.prototype.add.

  - ui/cinnamonDBus: Handle null xlet objects in
    CinnamonDBus.highlightXlet.

  - deskletManager: Initialise some variables and remove the
    variables that were initialised, probable typo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cinnamon packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cinnamon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cinnamon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cinnamon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cinnamon-gschemas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cinnamon-gschemas-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"cinnamon-3.4.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cinnamon-debuginfo-3.4.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cinnamon-debugsource-3.4.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cinnamon-gschemas-3.4.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cinnamon-gschemas-branding-upstream-3.4.6-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cinnamon / cinnamon-debuginfo / cinnamon-debugsource / etc");
}
