#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-45.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106072);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000420");

  script_name(english:"openSUSE Security Update : syncthing (openSUSE-2018-45)");
  script_summary(english:"Check for the openSUSE-2018-45 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for syncthing brings a new version and fixes the following
issues :

  - Update to version 0.14.42 :

  - Discovering new files in a deleted directory does not
    resurrect the directory (gh#syncthing/syncthing#4475).

  - 'Panic: interface conversion: *errors.errorString is not
    net.Error' after restart (gh#syncthing/syncthing#4561).

  - Auto-accept shared directories from trusted devices
    (gh#syncthing/syncthing#2299).

  - Empty directories in .stversions should be removed
    (gh#syncthing/syncthing#4406).

  - Human readable errors on attempted deletion of a
    non-empty directory (gh#syncthing/syncthing#4476).

  - Add confirmation on the Remove Folder / Device button
    (gh#syncthing/syncthing#4543).

  - Update to version 0.14.41 :

  - Devices with ignored files stay 'synchronising' forever
    (gh#syncthing/syncthing#623).

  - No Global Discovery without Synch Protocol Listen
    Address (gh#syncthing/syncthing#4418).

  - Local network classification doesn't always work
    (gh#syncthing/syncthing#4421).

  - Hashed GUI password should not be rehashed
    (gh#syncthing/syncthing#4458).

  - Pulls not triggered correctly on reconnection
    (gh#syncthing/syncthing#4504).

  - A symlink/file replacement doesn't work properly
    (gh#syncthing/syncthing#4505).

  - File/directory replacement doesn't work properly
    (gh#syncthing/syncthing#4506).

  - Logging at info level and above should always include
    context (gh#syncthing/syncthing#4510).

  - Panic in 'pfilter' package on 32 bit architectures
    (gh#syncthing/syncthing#4537).

  - Allow synchronising read-only directories as 'Master
    Directories' (gh#syncthing/syncthing#1126).

  - 'Global Changes' button is confusing, retitle to 'Recent
    Changes' (gh#syncthing/syncthing#4326).

  - Dial device addresses in parallel
    (gh#syncthing/syncthing#4456).

  - Avoid lots and lots of announced addresses in the
    presence of symmetric NAT (gh#syncthing/syncthing#4519).

  - Split transport usage reporting per stack
    (gh#syncthing/syncthing#4463).

  - Update to version 0.14.40 :

  - Report more data part of the anonymous usage report
    (gh#syncthing/syncthing#3628)

  - Better report synchronisation errors
    (gh#syncthing/syncthing#4392).

  - Removing paused directories no longer causes a panic
    (gh#syncthing/syncthing#4405).

  - Make local IPv4 discovery more resilient against write
    failures (gh#syncthing/syncthing#4414).

  - Clearer logging around config failures at startup
    (gh#syncthing/syncthing#4431).

  - Do not complain about inability to fsync files
    (gh#syncthing/syncthing#4432).

  - Improve KCP connections (gh#syncthing/syncthing#4446).

  - Improve directory health checking
    (gh#syncthing/syncthing#4451).

  - Include built-in support for file system notifications,
    although it is disabled by default.

  - Enable by default the UDP based 'KCP' protocol.

  - Update to version 0.14.39 :

  - Removing paused directories no longer triggers a crash
    (gh#syncthing/syncthing#4357).

  - Add further security related HTTP headers
    (gh#syncthing/syncthing#4360).

  - Improve info level logging in some cases
    (gh#syncthing/syncthing#4375).

  - Improve GUI tooltips in chromium based browsers
    (gh#syncthing/syncthing#4377).

  - Add -device-id command line switch
    (gh#syncthing/syncthing#4387).

  - Failure to upgrade directory markers from file to
    directory type is no longer fatal.

  - Update to version 0.14.38 :

  - KCP connections are now more stable
    (gh#syncthing/syncthing#4063,
    gh#syncthing/syncthing#4343)

  - Hashing benchmarks are skipped if a manual selection has
    been forced (gh#syncthing/syncthing#4348).

  - Relay server RAM usage has been reduced
    (gh#syncthing/syncthing#4245).

  - Update to version 0.14.37 (changes since 0.14.32) :

  - Relative version paths are now correctly relative to the
    directory path (gh#syncthing/syncthing#4188).

  - Remote devices now show bytes remaining to synchronise
    (gh#syncthing/syncthing#4227).

  - Editing ignore patterns no longer incorrectly shows
    included patterns (gh#syncthing/syncthing#4249).

  - The new directory dialogue now suggests a default path.
    Adjustable via advanced config defaultFolderPath
    (gh#syncthing/syncthing#2157).

  - The build script no longer sets -installsuffix by
    default (gh#syncthing/syncthing#4272).

  - Prevent a vulnerability that allows file overwrite via
    versioned symlinks (CVE-2017-1000420, boo#1074428,
    gh#syncthing/syncthing#4286).

  - Symlinks are deleted from versioned directories on
    startup (gh#syncthing/syncthing#4288).

  - Directory paths are no longer reset when editing a
    directory without a label (gh#syncthing/syncthing#4297).

  - Better detect synchronisation conflicts that happen
    while synchronising (gh#syncthing/syncthing#3742,
    gh#syncthing/syncthing#4305).

  - Fix a crash related to a nil reference in ignore
    handling (gh#syncthing/syncthing#4300).

  - Stop requiring golang.org/x/net/context.

  - Update to version 0.14.32 :

  - 'Nearby devices' are now shown in the add device
    dialogue, avoiding the need to type their device ID
    (gh#syncthing/syncthing#4157).

  - Directories that were once ignored in a sharing request
    now actually work properly when later added manually
    (gh#syncthing/syncthing#4219).

  - Update to version 0.14.31 (changes since 0.14.29) :

  - Correctly clear warning 'path is a subdirectory of other
    folder' in directory dialogue
    (gh#syncthing/syncthing#3433).

  - Conflict copies filename now includes the ID of the last
    device to change the file (gh#syncthing/syncthing#3524).

  - Directories offered by other devices can now be ignored
    (gh#syncthing/syncthing#3993).

  - Changed device name takes effect with restart; device
    name is not sent to unknown devices
    (gh#syncthing/syncthing#4164).

  - Correctly show CPU usage when started with -no-restart
    option (gh#syncthing/syncthing#4183).

  - Icons and directory information in local device summary
    is consistent with that in directories
    (gh#syncthing/syncthing#4100).

  - Fix a data race in KCP & STUN
    (gh#syncthing/syncthing#4177).

  - Ignore patterns on newly accepted directories are no
    longer erroneously inherited from an earlier added
    directory (gh#syncthing/syncthing#4203).

  - Update to version 0.14.29 :

  - The layout of the global changes dialogue is improved
    (gh#syncthing/syncthing#3895).

  - Running as root or SYSTEM now triggers a warning
    recommending against it (gh#syncthing/syncthing#4123).

  - Changing the theme no longer causes an HTTP error
    (gh#syncthing/syncthing#4127).

  - Update to version 0.14.28 :

  - It is now possible to create custom event subscriptions
    via the REST API (gh#syncthing/syncthing#1879).

  - Removing large directories now uses less memory
    (gh#syncthing/syncthing#2250).

  - The minimum disc space (per directory and for the home
    drive) can now be set to an absolute value
    (gh#syncthing/syncthing#3307).

  - Pausing or reconfiguring a directory will no longer
    start extra scans. Pausing a directory stops scanning
    (gh#syncthing/syncthing#3965).

  - Ignore patterns can now be set at directory creation
    time, and for paused directories
    (gh#syncthing/syncthing#3996).

  - It is no longer possible to configure the GUI/API to
    listen on a privileged port using the standard settings
    dialogue (gh#syncthing/syncthing#4020).

  - The device allowed subnet list can now include negative
    ('!') entries to disallow subnets
    (gh#syncthing/syncthing#4096).

  - Doing 'Override changes' now uses less memory
    (gh#syncthing/syncthing#4112).

  - Require golang.org/x/net/context on openSUSE older than
    openSUSE Leap 15.x.

  - Update to version 0.14.27 :

  - Devices can now have a list of allowed subnets (advanced
    config) (gh#syncthing/syncthing#219).

  - The transfer rate units can now be changed by clicking
    on the value (gh#syncthing/syncthing#234).

  - UI text explaining 'Introducer' is improved
    (gh#syncthing/syncthing#1819).

  - Advanced config editor can now edit lists of things
    (gh#syncthing/syncthing#2267).

  - Directories created for new directories now obey the
    user umask setting (gh#syncthing/syncthing#2519).

  - Incoming index updates are consistency checked better
    (gh#syncthing/syncthing#4053).

  - Update to version 0.14.26 :

  - Discovery errors are more clearly displayed in the GUI
    (gh#syncthing/syncthing#2344).

  - The language dropdown menu in the GUI is now correctly
    sorted (gh#syncthing/syncthing#3913).

  - When there are items that could not be synced, their
    full path is displayed in the GUI.

  - Update to version 0.14.25 :

  - Improve 'Pause All'/'Resume All' icons
    (gh#syncthing/syncthing#4003).

  - There are now mips and mipsle builds by default
    (gh#syncthing/syncthing#3959).

  - The 'overwriting protected files' warning now correctly
    handles relative paths to the config directory
    (gh#syncthing/syncthing#3183).

  - The experimental KCP protocol for transfers over UDP has
    been merged, although it's not currently enabled by
    default (gh#syncthing/syncthing#804).

  - Update to version 0.14.24 :

  - lib/sync: Fix a race in unlocker logging
    (gh#syncthing/syncthing#3884).

  - Make links and log messages refer to https instead of
    http where possible (gh#syncthing/syncthing#3976).

  - The default number of parallel file processing routines
    per directory is now two (previously one), and the
    number of simultaneously outstanding network requests
    has been increased.

  - The UI now contains buttons to pause or resume all
    directories with a single action.

  - Update to version 0.14.23 (changes since 0.14.21) :

  - Leading and trailing spaces are no longer stripped in
    the GUI password field (gh#syncthing/syncthing#3935)

  - The GUI shows remaining amount of data to sync per
    directory (gh#syncthing/syncthing#3908).

  - There should no longer be empty entries in the global
    log (gh#syncthing/syncthing#3933).

  - Weak hashing is now by default only enabled when it
    makes sense from a performance point of view
    (gh#syncthing/syncthing#3938).

  - Update to version 0.14.21 (changes since 0.14.19) :

  - There is now a warning when adding a directory that is a
    parent of an existing directory
    (gh#syncthing/syncthing#3197).

  - Using -logfile flag together with -no-restart now causes
    an error instead of silently failing
    (gh#syncthing/syncthing#3912).

  - Weak hashing is now disabled completely when the
    threshold percentage is > 100
    (gh#syncthing/syncthing#3891).

  - Rate limiting now actually works on ARM64 builds again
    (gh#syncthing/syncthing#3921).

  - Fix an issue where UPnP port allocations would be
    incorrect under some circumstances
    (gh#syncthing/syncthing#3924).

  - Weak hashing is a bit faster and allocates less memory.

  - The hashing performance reported at startup now includes
    weak hashing.

  - The GUI 'network error' dialogue no longer shows up as
    easily in some scenarios when using Syncthing behind a
    reverse proxy.

  - Update to version 0.14.19 :

  - Changing bandwidth rate limits now takes effect
    immediately without restart
    (gh#syncthing/syncthing#3846)

  - The event log (-audit) can now be directed to stderr for
    piping into an another application
    (gh#syncthing/syncthing#3859).

  - A panic on directory listing at startup has been fixed
    (gh#syncthing/syncthing#3584).

  - When a directory is deleted, the .stfolder marker is
    also removed. The ignore file and .stversions directory
    are retained, if present (gh#syncthing/syncthing#3857).

  - Several scenarios where a device would get stuck with
    'not a directory' errors are now handled again
    (gh#syncthing/syncthing#3819).

  - Third-party copyrights in the about box are now more up
    to date (gh#syncthing/syncthing#3839).

  - Hashing performance has been improved
    (gh#syncthing/syncthing#3861)

  - Update to version 0.14.18 :

  - Fix connections to older Syncthing versions being no
    longer closed due to an unmarshalling message: 'proto:
    wrong wireType = 2 for field BlockIndexes'
    (gh#syncthing/syncthing#3855).

  - Update to version 0.14.17 :

  - Panics caused by corrupt on disc database are now better
    explained in the panic message
    (gh#syncthing/syncthing#3689).

  - Statically configured device addresses without port
    number now correctly defaulted to port 22000 again
    (gh#syncthing/syncthing#3817).

  - Inotify clients no longer cause 'invalid subpath' errors
    to be displayed (gh#syncthing/syncthing#3829).

  - Directories can now be paused
    (gh#syncthing/syncthing#215).

  - 'Master' directories are now called 'send only' in order
    to standardise on a terminology of sending and receiving
    changes (gh#syncthing/syncthing#2679).

  - Pausing devices and directories now persists across
    restarts (gh#syncthing/syncthing#3407).

  - A rolling checksum is used to identify and reuse blocks
    that have moved within a file
    (gh#syncthing/syncthing#3527).

  - Syncthing allows setting the type-of-service field on
    outgoing packets, configured by the advanced setting
    'trafficClass' (gh#syncthing/syncthing#3790).

  - Which device introduced another device is now visible in
    the GUI (gh#syncthing/syncthing#3809)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074428"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected syncthing package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syncthing");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"syncthing-0.14.42-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"syncthing-0.14.42-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "syncthing");
}
