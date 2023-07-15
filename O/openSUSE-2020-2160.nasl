#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2160.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143514);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-12695", "CVE-2020-28926");
  script_xref(name:"CEA-ID", value:"CEA-2020-0050");

  script_name(english:"openSUSE Security Update : minidlna (openSUSE-2020-2160)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for minidlna fixes the following issues :

minidlna was updated to version 1.3.0 (boo#1179447)

  - Fixed some build warnings when building with musl.

  - Use $USER instead of $LOGNAME for the default friendly
    name.

  - Fixed build with GCC 10

  - Fixed some warnings from newer compilers

  - Disallow negative HTTP chunk lengths. [CVE-2020-28926]

  - Validate SUBSCRIBE callback URL. [CVE-2020-12695]

  - Fixed spurious warnings with ogg coverart

  - Fixed an issue with VLC where browse results would be
    truncated.

  - Fixed bookmarks on Samsung Q series

  - Added DSD file support.

  - Fixed potential stack smash vulnerability in
    getsyshwaddr on macOS.

  - Will now reload the log file on SIGHUP.

  - Worked around bad SearchCriteria from the Control4
    Android app.

  - Increased max supported network addresses to 8.

  - Added forced alphasort capability.

  - Added episode season and number metadata support.

  - Enabled subtitles by default for unknown DLNA clients,
    and add enable_subtitles config option.

  - Fixed discovery when connected to certain WiFi routers.

  - Added FreeBSD kqueue support.

  - Added the ability to set the group to run as.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179447");
  script_set_attribute(attribute:"solution", value:
"Update the affected minidlna packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12695");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:minidlna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:minidlna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:minidlna-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"minidlna-1.3.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"minidlna-debuginfo-1.3.0-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"minidlna-debugsource-1.3.0-lp152.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "minidlna / minidlna-debuginfo / minidlna-debugsource");
}
