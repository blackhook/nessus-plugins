#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-688.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149541);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-21404");

  script_name(english:"openSUSE Security Update : syncthing (openSUSE-2021-688)");
  script_summary(english:"Check for the openSUSE-2021-688 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for syncthing fixes the following issues :

Update to 1.15.0/1.15.1

  - This release fixes a vulnerability where Syncthing and
    the relay server can crash due to malformed relay
    protocol messages (CVE-2021-21404); see
    GHSA-x462-89pf-6r5h. (boo#1184428)

  - This release updates the CLI to use subcommands and adds
    the subcommands cli (previously standalone stcli
    utility) and decrypt (for offline verifying and
    decrypting encrypted folders).

  - With this release we invite everyone to test the
    'untrusted (encrypted) devices' feature. You should not
    use it yet on important production data. Thus UI
    controls are hidden behind a feature flag. For more
    information, visit:
    https://forum.syncthing.net/t/testing-untrusted-encrypte
    d-devices/16470 

Update to 1.14.0

  - This release adds configurable device and folder
    defaults.

  - The output format of the /rest/db/browse endpoint has
    changed. 

update to 1.13.1 :

  - This release adds configuration options for min/max
    connections (see
    https://docs.syncthing.net/advanced/option-connection-li
    mits.html) and moves the storage of pending
    devices/folders from the config to the database (see
    https://docs.syncthing.net/dev/rest.html#cluster-endpoin
    ts).

  - Bugfixes

  - Official builds of v1.13.0 come with the Tech Ui, which
    is impossible to switch back from

update to 1.12.1 :

  - Invalid names are allowed and 'auto accepted' in folder
    root path on Windows

  - Sometimes indexes for some folders aren't sent after
    starting Syncthing

  - [Untrusted] Remove Unexpected Items leaves things behind

  - Wrong theme on selection

  - Quic spamming address resolving

  - Deleted locally changed items still shown as locally
    changed

  - Allow specifying remote expected web UI port which would
    generate a href somewhere

  - Ignore fsync errors when saving ignore files 

Update to 1.12.0

  - The 1.12.0 release

  - adds a new config REST API.

  - The 1.11.0 release

  - adds the sendFullIndexOnUpgrade option to control
    whether all index data is resent when an upgrade is
    detected, equivalent to starting Syncthing with
    --reset-deltas. This (sendFullIndexOnUpgrade=true) used
    to be the behavior in previous versions, but is mainly
    useful as a troubleshooting step and causes high
    database churn. The new default is false.

  - Update to 1.10.0

  - This release adds the config option announceLANAddresses
    to enable (the default) or disable announcing private
    (RFC1918) LAN IP addresses to global discovery. 

  - Update to 1.9.0

  - This release adds the advanced folder option
    caseSensitiveFS
    (https://docs.syncthing.net/advanced/folder-caseSensitiv
    eFS.html) to disable the new safe handling of case
    insensitive filesystems. 

  - Fix Leap build by requiring at least Go 1.14

  - Prevent the build system to download Go modules which
    would require an internet connection during the build

  - Update to 1.8.0

  - The 1.8.0 release

  - adds the experimental copyRangeMethod config on folders,
    for use on filesystems with copy-on-write support.
    Please see
    https://docs.syncthing.net/advanced/folder-copyrangemeth
    od.html for details.

  - adds TCP hole punching, used to establish high
    performance TCP connections in certain NAT scenarios
    where only relay or QUIC connections could be used
    previously.

  - adds a configuration to file versioning for how often to
    run cleanup. This defaults to once an hour, but is
    configurable from very frequently to never.

  - The 1.7.0 release performs a database migration to
    optimize for clusters with many devices.

  - The 1.6.0 release performs a database schema migration,
    and adds the BlockPullOrder, DisableFsync and
    MaxConcurrentWrites folder options to the configuration
    schema. The LocalChangeDetected event no longer has the
    action set to added for new files, instead showing
    modified for all local file changes.

  - The 1.5.0 release changes the default location for the
    index database under some circumstances. Two new flags
    can also be used to affect the location of the
    configuration (-config) and database (-data) separately.
    The old -home flag is equivalent to setting both of
    these to the same directory. When no flags are given the
    following logic is used to determine the data location:
    If a database exists in the old default location, that
    location is still used. This means existing
    installations are not affected by this change. If
    $XDG_DATA_HOME is set, use $XDG_DATA_HOME/syncthing. If
    ~/.local/share/syncthing exists, use that location. Use
    the old default location.

  - Update to 1.4.2 :

  - Bugfixes :

  - #6499: panic: nil pointer dereference in usage reporting

  - Other issues :

  - revert a change to the upgrade code that puts
    unnecessary load on the upgrade server

  - Update to 1.4.1 :

  - Bugfixes :

  - #6289: 'general SOCKS server failure' since syncthing
    1.3.3

  - #6365: Connection errors not shown in GUI

  - #6415: Loop in database migration 'folder db index
    missing' after upgrade to v1.4.0

  - #6422: 'fatal error: runtime: out of memory' during
    database migration on QNAP NAS

  - Enhancements :

  - #5380: gui: Display folder/device name in modal

  - #5979: UNIX socket permission bits

  - #6384: Do auto upgrades early and synchronously on
    startup

  - Other issues :

  - #6249: Remove unnecessary RAM/CPU stats from GUI

  - Update to 1.4.0 :

  - Important changes :

  - New config option maxConcurrentIncomingRequestKiB

  - Replace config option maxConcurrentScans with
    maxFolderConcurrency

  - Improve database schema

  - Bugfixes :

  - #4774: Doesn't react to Ctrl-C when run in a subshell
    with -no-restart (Linux)

  - #5952: panic: Should never get a deleted file as needed
    when we don't have it

  - #6281: Progress emitter uses 100% CPU

  - #6300: lib/ignore: panic: runtime error: index out of
    range [0] with length 0

  - #6304: Syncing issues, database missing sequence entries

  - #6335: Crash or hard shutdown can case database
    inconsistency, out of sync

  - Enhancements :

  - #5786: Consider always running the monitor process

  - #5898: Database performance: reduce duplication

  - #5914: Limit folder concurrency to improve performance

  - #6302: Avoid thundering herd issue by global request
    limiter

  - Change the Go build requirement to a more flexible
    'golang(API) >= 1.12'."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.syncthing.net/advanced/folder-caseSensitiveFS.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.syncthing.net/advanced/folder-copyrangemethod.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.syncthing.net/advanced/option-connection-limits.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.syncthing.net/dev/rest.html#cluster-endpoints"
  );
  # https://forum.syncthing.net/t/testing-untrusted-encrypted-devices/16470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c4e0223"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected syncthing packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing-relaysrv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/08");
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

if ( rpm_check(release:"SUSE15.2", reference:"syncthing-1.15.1-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"syncthing-relaysrv-1.15.1-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "syncthing / syncthing-relaysrv");
}
