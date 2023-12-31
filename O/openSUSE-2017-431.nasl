#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-431.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99194);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3695", "CVE-2014-3696", "CVE-2014-3698", "CVE-2017-2640");
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"openSUSE Security Update : pidgin (openSUSE-2017-431)");
  script_summary(english:"Check for the openSUSE-2017-431 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pidgin fixes the following issues :

Feature update :

  - Update to GNOME 3.20.2 (fate#318572).

Security issues fixed :

  - CVE-2017-2640: Fix an out of bounds memory read in
    purple_markup_unescape_entity. (boo#1028835)

  - CVE-2014-3698: remote information leak via crafted XMPP
    message (boo#902408).

  - CVE-2014-3696: denial of service parsing Groupwise
    server message (boo#902410).

  - CVE-2014-3695: crash in MXit protocol plug-in
    (boo#902409).

Bugfixes

  - Correctly remove *.so files for plugins (fixes
    devel-file-in-non-devel-package).

  - Remove generation of a plugin list to package, simply
    add it all in %files with exclusions.

  - Build with GStreamer 1.x on SLE 12 SP2.

  - Fix SASL EXTERNAL fingerprint authentication
    (boo#1009974).

  - Use ALSA as default for avoiding broken volume control
    of pa sink (boo#886670)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=886670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902410"
  );
  # https://features.opensuse.org/318572
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-meanwhile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpurple-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"finch-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"finch-debuginfo-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"finch-devel-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-branding-upstream-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-debuginfo-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-devel-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-lang-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-meanwhile-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-meanwhile-debuginfo-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-tcl-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpurple-tcl-debuginfo-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pidgin-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pidgin-debuginfo-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pidgin-debugsource-2.10.11-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pidgin-devel-2.10.11-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-debuginfo / finch-devel / libpurple / etc");
}
