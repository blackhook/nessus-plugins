#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-656.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100658);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7178", "CVE-2017-9031");

  script_name(english:"openSUSE Security Update : deluge (openSUSE-2017-656)");
  script_summary(english:"Check for the openSUSE-2017-656 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for deluge fixes two security issues :

  - CVE-2017-9031: A remote attacker may have used a
    directory traversal vulnerability in the web interface
    (bsc#1039815)

  - CVE-2017-7178: A remote attacher could have exploited a
    CSRF vulnerability to trick a logged-in user to perform
    actions in the WebUI (bsc#1039958)

In addition, deluge was updated to 1.3.15 with the following fixes and
changes :

  - Core: Fix issues with displaying libtorrent-rasterbar
    single proxy.

  - Core: Fix libtorrent-rasterbar 1.2 trackers crashing
    Deluge UIs.

  - Core: Fix an error in torrent priorities causing file
    priority mismatch in UIs.

  - GtkUI: Fix column sort state not saved in Thinclient
    mode.

  - GtkUI: Fix a connection manager error with malformed ip.

  - GtkUI: Rename SystemTray/Indicator 'Pause/Resume All' to
    'Pause/Resume Session'.

  - GtkUI: Workaround libtorrent-rasterbar single proxy by
    greying out unused proxy types.

  - Notification Plugin: Fix webui passing string for int
    port value.

  - AutoAdd Plugin: Add WebUI preferences page detailing
    lack of configuration via WebUI.

  - Label Plugin: Add WebUI preferences page detailing how
    to configure plugin.

  - Core: Fix 'Too many files open' errors.

  - Core: Add support for python-GeoIP for use with
    libtorrent 1.1.

  - Core: Fix a single proxy entry being overwritten
    resulting in no proxy set.

  - UI: Add the tracker_status translation to UIs.

  - GtkUI: Strip whitespace from infohash before checks.

  - GtkUI: Add a missed feature autofill infohash entry from
    clipboard.

  - WebUI: Backport bind interface option for server.

  - ConsoleUI: Fix a decode error comparing non-ascii (str)
    torrent names.

  - AutoAdd Plugin: Fixes for splitting magnets from file.

  - Remove the duplicate magnet extension when splitting.

  - Remove deluge-libtorrent-1.1-geoip.patch: fixed
    upstream."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039958"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected deluge packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deluge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:deluge-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"deluge-1.3.15-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"deluge-lang-1.3.15-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "deluge / deluge-lang");
}
