#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2008.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143289);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_cve_id("CVE-2020-28924");

  script_name(english:"openSUSE Security Update : rclone (openSUSE-2020-2008)");
  script_summary(english:"Check for the openSUSE-2020-2008 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for rclone fixes the following issues :

rclone was updated to version 1.53.3 :

  - Bug Fixes

  - Fix incorrect use of math/rand instead of crypto/rand
    CVE-2020-28924 boo#1179005 (Nick Craig-Wood)

  - Check https://github.com/rclone/passwordcheck for a tool
    check for weak passwords generated by rclone

  - VFS

  - Fix vfs/refresh calls with fs= parameter (Nick
    Craig-Wood)

  - Sharefile

  - Fix backend due to API swapping integers for strings
    (Nick Craig-Wood)

Update to 1.53.2 :

  - Bug Fixes

  - accounting

  + Fix incorrect speed and transferTime in core/stats (Nick
    Craig-Wood)

  + Stabilize display order of transfers on Windows (Nick
    Craig-Wood)

  - operations

  + Fix use of --suffix without --backup-dir (Nick
    Craig-Wood)

  + Fix spurious '--checksum is in use but the source and
    destination have no hashes in common' (Nick Craig-Wood)

  - build

  + Work around GitHub actions brew problem (Nick
    Craig-Wood)

  + Stop using set-env and set-path in the GitHub actions
    (Nick Craig-Wood)

  - Mount

  - mount2: Fix the swapped UID / GID values (Russell
    Cattelan)

  - VFS

  - Detect and recover from a file being removed externally
    from the cache (Nick Craig-Wood)

  - Fix a deadlock vulnerability in downloaders.Close (Leo
    Luan)

  - Fix a race condition in retryFailedResets (Leo Luan)

  - Fix missed concurrency control between some item
    operations and reset (Leo Luan)

  - Add exponential backoff during ENOSPC retries (Leo Luan)

  - Add a missed update of used cache space (Leo Luan)

  - Fix --no-modtime to not attempt to set modtimes (as
    documented) (Nick Craig-Wood)

  - Local

  - Fix sizes and syncing with --links option on Windows
    (Nick Craig-Wood)

  - Chunker

  - Disable ListR to fix missing files on GDrive
    (workaround) (Ivan Andreev)

  - Fix upload over crypt (Ivan Andreev)

  - Fichier

  - Increase maximum file size from 100GB to 300GB (gyutw)

  - Jottacloud

  - Remove clientSecret from config when upgrading to token
    based authentication (buengese)

  - Avoid double url escaping of device/mountpoint
    (albertony)

  - Remove DirMove workaround as it's not required anymore -
    also (buengese)

  - Mailru

  - Fix uploads after recent changes on server (Ivan
    Andreev)

  - Fix range requests after june changes on server (Ivan
    Andreev)

  - Fix invalid timestamp on corrupted files (fixes) (Ivan
    Andreev)

  - Onedrive

  - Fix disk usage for sharepoint (Nick Craig-Wood)

  - S3

  - Add missing regions for AWS (Anagh Kumar Baranwal)

  - Seafile

  - Fix accessing libraries > 2GB on 32 bit systems (Muffin
    King)

  - SFTP

  - Always convert the checksum to lower case (buengese)

  - Union

  - Create root directories if none exist (Nick Craig-Wood)

Update to version 1.53.1 :

  - Bug Fixes

  - accounting: Remove new line from end of --stats-one-line
    display

  - VFS

  - Fix spurious error 'vfs cache: failed to _ensure cache
    EOF'

  - Log an ERROR if we fail to set the file to be sparse

  - Local

  - Log an ERROR if we fail to set the file to be sparse

  - Drive

  - Re-adds special oauth help text

  - Opendrive

  - Do not retry 400 errors

Update to version 1.53.0

  - New Features

  - The VFS layer was heavily reworked for this release -
    see below for more details

  - Interactive mode -i/--interactive for destructive
    operations (fishbullet)

  - Add --bwlimit-file flag to limit speeds of individual
    file transfers (Nick Craig-Wood)

  - Transfers are sorted by start time in the stats and
    progress output (Max Sum)

  - Make sure backends expand ~ and environment vars in file
    names they use (Nick Craig-Wood)

  - Add --refresh-times flag to set modtimes on hashless
    backends (Nick Craig-Wood)

  - rclone check

  + Add reporting of filenames for same/missing/changed
    (Nick Craig-Wood)

  + Make check command obey --dry-run/-i/--interactive (Nick
    Craig-Wood)

  + Make check do --checkers files concurrently (Nick
    Craig-Wood)

  + Retry downloads if they fail when using the --download
    flag (Nick Craig-Wood)

  + Make it show stats by default (Nick Craig-Wood)

  - rclone config

  + Set RCLONE_CONFIG_DIR for use in config files and
    subprocesses (Nick Craig-Wood)

  + Reject remote names starting with a dash. (jtagcat)

  - rclone cryptcheck: Add reporting of filenames for
    same/missing/changed (Nick Craig-Wood)

  - rclone dedupe: Make it obey the --size-only flag for
    duplicate detection (Nick Craig-Wood)

  - rclone link: Add --expire and --unlink flags (Roman
    Kredentser)

  - rclone mkdir: Warn when using mkdir on remotes which
    can't have empty directories (Nick Craig-Wood)

  - rclone rc: Allow JSON parameters to simplify command
    line usage (Nick Craig-Wood)

  - rclone serve ftp

  + Don't compile on < go1.13 after dependency update (Nick
    Craig-Wood)

  + Add error message if auth proxy fails (Nick Craig-Wood)

  + Use refactored goftp.io/server library for binary shrink
    (Nick Craig-Wood)

  - rclone serve restic: Expose interfaces so that rclone
    can be used as a library from within restic (Jack)

  - rclone sync: Add --track-renames-strategy leaf (Nick
    Craig-Wood)

  - rclone touch: Add ability to set nanosecond resolution
    times (Nick Craig-Wood)

  - rclone tree: Remove -i shorthand for --noindent as it
    conflicts with -i/--interactive (Nick Craig-Wood)

  - Bug Fixes

  - Mount

  - rc interface

  + Add call for unmount all (Chaitanya Bankanhal)

  + Make mount/mount remote control take vfsOpt option (Nick
    Craig-Wood)

  + Add mountOpt to mount/mount (Nick Craig-Wood)

  + Add VFS and Mount options to mount/listmounts (Nick
    Craig-Wood)

  - Catch panics in cgofuse initialization and turn into
    error messages (Nick Craig-Wood)

  - Always supply stat information in Readdir (Nick
    Craig-Wood)

  - Add support for reading unknown length files using
    direct IO (Windows) (Nick Craig-Wood)

  - Fix On Windows don't add -o uid/gid=-1 if user supplies
    -o uid/gid. (Nick Craig-Wood)

  - Fix volume name broken in recent refactor (Nick
    Craig-Wood)

  - VFS

  - Implement partial reads for --vfs-cache-mode full (Nick
    Craig-Wood)

  - Add --vfs-writeback option to delay writes back to cloud
    storage (Nick Craig-Wood)

  - Add --vfs-read-ahead parameter for use with
    --vfs-cache-mode full (Nick Craig-Wood)

  - Restart pending uploads on restart of the cache (Nick
    Craig-Wood)

  - Support synchronous cache space recovery upon ENOSPC
    (Leo Luan)

  - Allow ReadAt and WriteAt to run concurrently with
    themselves (Nick Craig-Wood)

  - Change modtime of file before upload to current (Rob
    Calistri)

  - Recommend --vfs-cache-modes writes on backends which
    can't stream (Nick Craig-Wood)

  - Add an optional fs parameter to vfs rc methods (Nick
    Craig-Wood)

  - Fix errors when using > 260 char files in the cache in
    Windows (Nick Craig-Wood)

  - Fix renaming of items while they are being uploaded
    (Nick Craig-Wood)

  - Fix very high load caused by slow directory listings
    (Nick Craig-Wood)

  - Fix renamed files not being uploaded with
    --vfs-cache-mode minimal (Nick Craig-Wood)

  - Fix directory locking caused by slow directory listings
    (Nick Craig-Wood)

  - Fix saving from chrome without --vfs-cache-mode writes
    (Nick Craig-Wood)

  - Crypt Add --crypt-server-side-across-configs flag (Nick
    Craig-Wood) Make any created backends be cached to fix
    rc problems (Nick Craig-Wood)

  - Azure Blob Don't compile on < go1.13 after dependency
    update (Nick Craig-Wood)

  - B2 Implement server side copy for files > 5GB (Nick
    Craig-Wood) Cancel in progress multipart uploads and
    copies on rclone exit (Nick Craig-Wood) Note that b2's
    encoding now allows \ but rclone's hasn't changed (Nick
    Craig-Wood) Fix transfers when using download_url (Nick
    Craig-Wood)

  - Box

  - Implement rclone cleanup (buengese)

  - Cancel in progress multipart uploads and copies on
    rclone exit (Nick Craig-Wood)

  - Allow authentication with access token (David)

  - Chunker

  - Make any created backends be cached to fix rc problems
    (Nick Craig-Wood)

  - Drive

  - Add rclone backend drives to list shared drives
    (teamdrives) (Nick Craig-Wood)

  - Implement rclone backend untrash (Nick Craig-Wood)

  - Work around drive bug which didn't set modtime of copied
    docs (Nick Craig-Wood)

  - Added --drive-starred-only to only show starred files
    (Jay McEntire)

  - Deprecate --drive-alternate-export as it is no longer
    needed (themylogin)

  - Fix duplication of Google docs on server side copy (Nick
    Craig-Wood)

  - Fix 'panic: send on closed channel' when recycling dir
    entries (Nick Craig-Wood)

  - Dropbox

  - Add copyright detector info in limitations section in
    the docs (Alex Guerrero)

  - Fix rclone link by removing expires parameter (Nick
    Craig-Wood)

  - Fichier

  - Detect Flood detected: IP Locked error and sleep for 30s
    (Nick Craig-Wood)

  - FTP

  - Add explicit TLS support (Heiko Bornholdt)

  - Add support for --dump bodies and --dump auth for
    debugging (Nick Craig-Wood)

  - Fix interoperation with pure-ftpd (Nick Craig-Wood)

  - Google Cloud Storage

  - Add support for anonymous access (Kai L&uuml;ke)

  - Jottacloud

  - Bring back legacy authentification for use with
    whitelabel versions (buengese)

  - Switch to new api root - also implement a very ugly
    workaround for the DirMove failures (buengese)

  - Onedrive

  - Rework cancel of multipart uploads on rclone exit (Nick
    Craig-Wood)

  - Implement rclone cleanup (Nick Craig-Wood)

  - Add --onedrive-no-versions flag to remove old versions
    (Nick Craig-Wood)

  - Pcloud

  - Implement rclone link for public link creation
    (buengese)

  - Qingstor

  - Cancel in progress multipart uploads on rclone exit
    (Nick Craig-Wood)

  - S3

  - Preserve metadata when doing multipart copy (Nick
    Craig-Wood)

  - Cancel in progress multipart uploads and copies on
    rclone exit (Nick Craig-Wood)

  - Add rclone link for public link sharing (Roman
    Kredentser)

  - Add rclone backend restore command to restore objects
    from GLACIER (Nick Craig-Wood)

  - Add rclone cleanup and rclone backend cleanup to clean
    unfinished multipart uploads (Nick Craig-Wood)

  - Add rclone backend list-multipart-uploads to list
    unfinished multipart uploads (Nick Craig-Wood)

  - Add --s3-max-upload-parts support (Kamil
    Trzci&#x144;ski)

  - Add --s3-no-check-bucket for minimising rclone
    transactions and perms (Nick Craig-Wood)

  - Add --s3-profile and --s3-shared-credentials-file
    options (Nick Craig-Wood)

  - Use regional s3 us-east-1 endpoint (David)

  - Add Scaleway provider (Vincent Feltz)

  - Update IBM COS endpoints (Egor Margineanu)

  - Reduce the default --s3-copy-cutoff to < 5GB for
    Backblaze S3 compatibility (Nick Craig-Wood)

  - Fix detection of bucket existing (Nick Craig-Wood)

  - SFTP

  - Use the absolute path instead of the relative path for
    listing for improved compatibility (Nick Craig-Wood)

  - Add --sftp-subsystem and --sftp-server-command options
    (aus)

  - Swift

  - Fix dangling large objects breaking the listing (Nick
    Craig-Wood)

  - Fix purge not deleting directory markers (Nick
    Craig-Wood)

  - Fix update multipart object removing all of its own
    parts (Nick Craig-Wood)

  - Fix missing hash from object returned from upload (Nick
    Craig-Wood)

  - Tardigrade

  - Upgrade to uplink v1.2.0 (Kaloyan Raev)

  - Union

  - Fix writing with the all policy (Nick Craig-Wood)

  - WebDAV

  - Fix directory creation with 4shared (Nick Craig-Wood)

  - Update to version 1.52.3

  - Bug Fixes

  - docs

  + Disable smart typography (eg en-dash) in MANUAL.* and
    man page (Nick Craig-Wood)

  + Update install.md to reflect minimum Go version (Evan
    Harris)

  + Update install from source instructions (Nick
    Craig-Wood)

  + make_manual: Support SOURCE_DATE_EPOCH (Morten Linderud)

  - log: Fix --use-json-log going to stderr not --log-file
    on Windows (Nick Craig-Wood)

  - serve dlna: Fix file list on Samsung Series 6+ TVs
    (Matteo Pietro Dazzi)

  - sync: Fix deadlock with --track-renames-strategy modtime
    (Nick Craig-Wood)

  - Cache

  - Fix moveto/copyto remote:file remote:file2 (Nick
    Craig-Wood)

  - Drive

  - Stop using root_folder_id as a cache (Nick Craig-Wood)

  - Make dangling shortcuts appear in listings (Nick
    Craig-Wood)

  - Drop 'Disabling ListR' messages down to debug (Nick
    Craig-Wood)

  - Workaround and policy for Google Drive API (Dmitry
    Ustalov)

  - FTP

  - Add note to docs about home vs root directory selection
    (Nick Craig-Wood)

  - Onedrive

  - Fix reverting to Copy when Move would have worked (Nick
    Craig-Wood)

  - Avoid comma rendered in URL in onedrive.md (Kevin)

  - Pcloud

  - Fix oauth on European region 'eapi.pcloud.com' (Nick
    Craig-Wood)

  - S3

  - Fix bucket Region auto detection when Region unset in
    config (Nick Craig-Wood)

  - Update to version 1.52.2

  - Bug Fixes

  - build

  + Fix docker release build action (Nick Craig-Wood)

  + Fix custom timezone in Docker image (NoLooseEnds)

  - check: Fix misleading message which printed errors
    instead of differences (Nick Craig-Wood)

  - errors: Add WSAECONNREFUSED and more to the list of
    retriable Windows errors (Nick Craig-Wood)

  - rcd: Fix incorrect prometheus metrics (Gary Kim)

  - serve restic: Fix flags so they use environment
    variables (Nick Craig-Wood)

  - serve webdav: Fix flags so they use environment
    variables (Nick Craig-Wood)

  - sync: Fix --track-renames-strategy modtime (Nick
    Craig-Wood)

  - Drive

  - Fix not being able to delete a directory with a trashed
    shortcut (Nick Craig-Wood)

  - Fix creating a directory inside a shortcut (Nick
    Craig-Wood)

  - Fix --drive-impersonate with cached root_folder_id (Nick
    Craig-Wood)

  - SFTP

  - Fix SSH key PEM loading (Zac Rubin)

  - Swift

  - Speed up deletes by not retrying segment container
    deletes (Nick Craig-Wood)

  - Tardigrade

  - Upgrade to uplink v1.1.1 (Caleb Case)

  - WebDAV

  - Fix free/used display for rclone about/df for certain
    backends (Nick Craig-Wood)

  - Update to version 1.52.1

  - VFS

  - Fix OS vs Unix path confusion - fixes ChangeNotify on
    Windows (Nick Craig-Wood)

  - Drive

  - Fix missing items when listing using --fast-list / ListR
    (Nick Craig-Wood)

  - Putio

  - Fix panic on Object.Open (Cenk Alti)

  - S3

  - Fix upload of single files into buckets without create
    permission (Nick Craig-Wood)

  - Fix --header-upload (Nick Craig-Wood)

  - Tardigrade

  - Fix listing bug by upgrading to v1.0.7

  - Set UserAgent to rclone (Caleb Case)

  - Update to version 1.52.0

  - New backends

  - Tardigrade backend for use with storj.io (Caleb Case)

  - Union re-write to have multiple writable remotes (Max
    Sum)

  - Seafile for Seafile server (Fred @creativeprojects)

  - New commands

  - backend: command for backend specific commands (see
    backends) (Nick Craig-Wood)

  - cachestats: Deprecate in favour of rclone backend stats
    cache: (Nick Craig-Wood)

  - dbhashsum: Deprecate in favour of rclone hashsum
    DropboxHash (Nick Craig-Wood)

  - New Features

  - Add --header-download and --header-upload flags for
    setting HTTP headers when uploading/downloading (Tim
    Gallant)

  - Add --header flag to add HTTP headers to every HTTP
    transaction (Nick Craig-Wood)

  - Add --check-first to do all checking before starting
    transfers (Nick Craig-Wood)

  - Add --track-renames-strategy for configurable matching
    criteria for --track-renames (Bernd Schoolmann)

  - Add --cutoff-mode hard,soft,catious (Shing Kit Chan &
    Franklyn Tackitt)

  - Filter flags (eg --files-from -) can read from stdin
    (fishbullet)

  - Add --error-on-no-transfer option (Jon Fautley)

  - Implement --order-by xxx,mixed for copying some small
    and some big files (Nick Craig-Wood)

  - Allow --max-backlog to be negative meaning as large as
    possible (Nick Craig-Wood)

  - Added --no-unicode-normalization flag to allow Unicode
    filenames to remain unique (Ben Zenker)

  - Allow --min-age/--max-age to take a date as well as a
    duration (Nick Craig-Wood)

  - Add rename statistics for file and directory renames
    (Nick Craig-Wood)

  - Add statistics output to JSON log (reddi)

  - Make stats be printed on non-zero exit code (Nick
    Craig-Wood)

  - When running --password-command allow use of stdin
    (S&eacute;bastien Gross)

  - Stop empty strings being a valid remote path (Nick
    Craig-Wood)

  - accounting: support WriterTo for less memory copying
    (Nick Craig-Wood)

  - build

  + Update to use go1.14 for the build (Nick Craig-Wood)

  + Add -trimpath to release build for reproduceable builds
    (Nick Craig-Wood)

  + Remove GOOS and GOARCH from Dockerfile (Brandon Philips)

  - config

  + Fsync the config file after writing to save more
    reliably (Nick Craig-Wood)

  + Add --obscure and --no-obscure flags to config
    create/update (Nick Craig-Wood)

  + Make config show take remote: as well as remote (Nick
    Craig-Wood)

  - copyurl: Add --no-clobber flag (Denis)

  - delete: Added --rmdirs flag to delete directories as
    well (Kush)

  - filter: Added --files-from-raw flag (Ankur Gupta)

  - genautocomplete: Add support for fish shell (Matan
    Rosenberg)

  - log: Add support for syslog LOCAL facilities (Patryk
    Jakuszew)

  - lsjson: Add --hash-type parameter and use it in lsf to
    speed up hashing (Nick Craig-Wood)

  - rc

  + Add -o/--opt and -a/--arg for more structured input
    (Nick Craig-Wood)

  + Implement backend/command for running backend specific
    commands remotely (Nick Craig-Wood)

  + Add mount/mount command for starting rclone mount via
    the API (Chaitanya)

  - rcd: Add Prometheus metrics support (Gary Kim)

  - serve http

  + Added a --template flag for user defined markup
    (calistri)

  + Add Last-Modified headers to files and directories (Nick
    Craig-Wood)

  - serve sftp: Add support for multiple host keys by
    repeating --key flag (Maxime Suret)

  - touch: Add --localtime flag to make --timestamp
    localtime not UTC (Nick Craig-Wood)

  - Bug Fixes

  - accounting

  + Restore 'Max number of stats groups reached' log line
    (Micha&#x142; Matczuk)

  + Correct exitcode on Transfer Limit Exceeded flag. (Anuar
    Serdaliyev)

  + Reset bytes read during copy retry (Ankur Gupta)

  + Fix race clearing stats (Nick Craig-Wood)

  - copy: Only create empty directories when they don't
    exist on the remote (Ishuah Kariuki)

  - dedupe: Stop dedupe deleting files with identical IDs
    (Nick Craig-Wood)

  - oauth

  + Use custom http client so that --no-check-certificate is
    honored by oauth token fetch (Mark Spieth)

  + Replace deprecated oauth2.NoContext (Lars Lehtonen)

  - operations

  + Fix setting the timestamp on Windows for multithread
    copy (Nick Craig-Wood)

  + Make rcat obey --ignore-checksum (Nick Craig-Wood)

  + Make --max-transfer more accurate (Nick Craig-Wood)

  - rc

  + Fix dropped error (Lars Lehtonen)

  + Fix misplaced http server config (Xiaoxing Ye)

  + Disable duplicate log (ElonH)

  - serve dlna

  + Cds: don't specify childCount at all when unknown (Dan
    Walters)

  + Cds: use modification time as date in dlna metadata (Dan
    Walters)

  - serve restic: Fix tests after restic project removed
    vendoring (Nick Craig-Wood)

  - sync

  + Fix incorrect 'nothing to transfer' message using
    --delete-before (Nick Craig-Wood)

  + Only create empty directories when they don't exist on
    the remote (Ishuah Kariuki)

  - Mount

  - Add --async-read flag to disable asynchronous reads
    (Nick Craig-Wood)

  - Ignore --allow-root flag with a warning as it has been
    removed upstream (Nick Craig-Wood)

  - Warn if --allow-non-empty used on Windows and clarify
    docs (Nick Craig-Wood)

  - Constrain to go1.13 or above otherwise bazil.org/fuse
    fails to compile (Nick Craig-Wood)

  - Fix fail because of too long volume name (evileye)

  - Report 1PB free for unknown disk sizes (Nick Craig-Wood)

  - Map more rclone errors into file systems errors (Nick
    Craig-Wood)

  - Fix disappearing cwd problem (Nick Craig-Wood)

  - Use ReaddirPlus on Windows to improve directory listing
    performance (Nick Craig-Wood)

  - Send a hint as to whether the filesystem is case
    insensitive or not (Nick Craig-Wood)

  - Add rc command mount/types (Nick Craig-Wood)

  - Change maximum leaf name length to 1024 bytes (Nick
    Craig-Wood)

  - VFS

  - Add --vfs-read-wait and --vfs-write-wait flags to
    control time waiting for a sequential read/write (Nick
    Craig-Wood)

  - Change default --vfs-read-wait to 20ms (it was 5ms and
    not configurable) (Nick Craig-Wood)

  - Make df output more consistent on a rclone mount. (Yves
    G)

  - Report 1PB free for unknown disk sizes (Nick Craig-Wood)

  - Fix race condition caused by unlocked reading of
    Dir.path (Nick Craig-Wood)

  - Make File lock and Dir lock not overlap to avoid
    deadlock (Nick Craig-Wood)

  - Implement lock ordering between File and Dir to
    eliminate deadlocks (Nick Craig-Wood)

  - Factor the vfs cache into its own package (Nick
    Craig-Wood)

  - Pin the Fs in use in the Fs cache (Nick Craig-Wood)

  - Add SetSys() methods to Node to allow caching stuff on a
    node (Nick Craig-Wood)

  - Ignore file not found errors from Hash in Read.Release
    (Nick Craig-Wood)

  - Fix hang in read wait code (Nick Craig-Wood)

  - Local

  - Speed up multi thread downloads by using sparse files on
    Windows (Nick Craig-Wood)

  - Implement --local-no-sparse flag for disabling sparse
    files (Nick Craig-Wood)

  - Implement rclone backend noop for testing purposes (Nick
    Craig-Wood)

  - Fix 'file not found' errors on post transfer Hash
    calculation (Nick Craig-Wood)

  - Cache

  - Implement rclone backend stats command (Nick Craig-Wood)

  - Fix Server Side Copy with Temp Upload (Brandon McNama)

  - Remove Unused Functions (Lars Lehtonen)

  - Disable race tests until bbolt is fixed (Nick
    Craig-Wood)

  - Move methods used for testing into test file (greatroar)

  - Add Pin and Unpin and canonicalised lookup (Nick
    Craig-Wood)

  - Use proper import path go.etcd.io/bbolt
    (Robert-Andr&eacute; Mauchin)

  - Crypt

  - Calculate hashes for uploads from local disk (Nick
    Craig-Wood)

  + This allows crypted Jottacloud uploads without using
    local disk

  + This means crypted s3/b2 uploads will now have hashes

  - Added rclone backend decode/encode commands to replicate
    functionality of cryptdecode (Anagh Kumar Baranwal)

  - Get rid of the unused Cipher interface as it obfuscated
    the code (Nick Craig-Wood)

  - Azure Blob

  - Implement streaming of unknown sized files so rcat is
    now supported (Nick Craig-Wood)

  - Implement memory pooling to control memory use (Nick
    Craig-Wood)

  - Add --azureblob-disable-checksum flag (Nick Craig-Wood)

  - Retry InvalidBlobOrBlock error as it may indicate block
    concurrency problems (Nick Craig-Wood)

  - Remove unused Object.parseTimeString() (Lars Lehtonen)

  - Fix permission error on SAS URL limited to container
    (Nick Craig-Wood)

  - B2

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Ignore directory markers at the root also (Nick
    Craig-Wood)

  - Force the case of the SHA1 to lowercase (Nick
    Craig-Wood)

  - Remove unused largeUpload.clearUploadURL() (Lars
    Lehtonen)

  - Box

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Implement About to read size used (Nick Craig-Wood)

  - Add token renew function for jwt auth (David Bramwell)

  - Added support for interchangeable root folder for Box
    backend (Sunil Patra)

  - Remove unnecessary iat from jws claims (David)

  - Drive

  - Follow shortcuts by default, skip with
    --drive-skip-shortcuts (Nick Craig-Wood)

  - Implement rclone backend shortcut command for creating
    shortcuts (Nick Craig-Wood)

  - Added rclone backend command to change
    service_account_file and chunk_size (Anagh Kumar
    Baranwal)

  - Fix missing files when using --fast-list and
    --drive-shared-with-me (Nick Craig-Wood)

  - Fix duplicate items when using --drive-shared-with-me
    (Nick Craig-Wood)

  - Extend --drive-stop-on-upload-limit to respond to
    teamDriveFileLimitExceeded. (harry)

  - Don't delete files with multiple parents to avoid data
    loss (Nick Craig-Wood)

  - Server side copy docs use default description if empty
    (Nick Craig-Wood)

  - Dropbox

  - Make error insufficient space to be fatal (harry)

  - Add info about required redirect url (Elan
    Ruusam&auml;e)

  - Fichier

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Implement custom pacer to deal with the new rate
    limiting (buengese)

  - FTP

  - Fix lockup when using concurrency limit on failed
    connections (Nick Craig-Wood)

  - Fix lockup on failed upload when using concurrency limit
    (Nick Craig-Wood)

  - Fix lockup on Close failures when using concurrency
    limit (Nick Craig-Wood)

  - Work around pureftp sending spurious 150 messages (Nick
    Craig-Wood)

  - Google Cloud Storage

  - Add support for --header-upload and --header-download
    (Nick Craig-Wood)

  - Add ARCHIVE storage class to help (Adam Stroud)

  - Ignore directory markers at the root (Nick Craig-Wood)

  - Googlephotos

  - Make the start year configurable (Daven)

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Create feature/favorites directory (Brandon Philips)

  - Fix 'concurrent map write' error (Nick Craig-Wood)

  - Don't put an image in error message (Nick Craig-Wood)

  - HTTP

  - Improved directory listing with new template from Caddy
    project (calisro)

  - Jottacloud

  - Implement --jottacloud-trashed-only (buengese)

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Use RawURLEncoding when decoding base64 encoded login
    token (buengese)

  - Implement cleanup (buengese)

  - Update docs regarding cleanup, removed remains from old
    auth, and added warning about special mountpoints.
    (albertony)

  - Mailru

  - Describe 2FA requirements (valery1707)

  - Onedrive

  - Implement --onedrive-server-side-across-configs (Nick
    Craig-Wood)

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Fix occasional 416 errors on multipart uploads (Nick
    Craig-Wood)

  - Added maximum chunk size limit warning in the docs
    (Harry)

  - Fix missing drive on config (Nick Craig-Wood)

  - Make error quotaLimitReached to be fatal (harry)

  - Opendrive

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Pcloud

  - Added support for interchangeable root folder for pCloud
    backend (Sunil Patra)

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Fix initial config 'Auth state doesn't match' message
    (Nick Craig-Wood)

  - Premiumizeme

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Prune unused functions (Lars Lehtonen)

  - Putio

  - Add support for --header-upload and --header-download
    (Nick Craig-Wood)

  - Make downloading files use the rclone http Client (Nick
    Craig-Wood)

  - Fix parsing of remotes with leading and trailing / (Nick
    Craig-Wood)

  - Qingstor

  - Make rclone cleanup remove pending multipart uploads
    older than 24h (Nick Craig-Wood)

  - Try harder to cancel failed multipart uploads (Nick
    Craig-Wood)

  - Prune multiUploader.list() (Lars Lehtonen)

  - Lint fix (Lars Lehtonen)

  - S3

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Use memory pool for buffer allocations (Maciej Zimnoch)

  - Add SSE-C support for AWS, Ceph, and MinIO (Jack
    Anderson)

  - Fail fast multipart upload (Micha&#x142; Matczuk)

  - Report errors on bucket creation (mkdir) correctly (Nick
    Craig-Wood)

  - Specify that Minio supports URL encoding in listings
    (Nick Craig-Wood)

  - Added 500 as retryErrorCode (Micha&#x142; Matczuk)

  - Use --low-level-retries as the number of SDK retries
    (Aleksandar Jankovi&#x107;)

  - Fix multipart abort context (Aleksandar Jankovic)

  - Replace deprecated session.New() with
    session.NewSession() (Lars Lehtonen)

  - Use the provided size parameter when allocating a new
    memory pool (Joachim Brandon LeBlanc)

  - Use rclone's low level retries instead of AWS SDK to fix
    listing retries (Nick Craig-Wood)

  - Ignore directory markers at the root also (Nick
    Craig-Wood)

  - Use single memory pool (Micha&#x142; Matczuk)

  - Do not resize buf on put to memBuf (Micha&#x142;
    Matczuk)

  - Improve docs for --s3-disable-checksum (Nick Craig-Wood)

  - Don't leak memory or tokens in edge cases for multipart
    upload (Nick Craig-Wood)

  - Seafile

  - Implement 2FA (Fred)

  - SFTP

  - Added --sftp-pem-key to support inline key files
    (calisro)

  - Fix post transfer copies failing with 0 size when using
    set_modtime=false (Nick Craig-Wood)

  - Sharefile

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Sugarsync

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Swift

  - Add support for --header-upload and --header-download
    (Nick Craig-Wood)

  - Fix cosmetic issue in error message (Martin Michlmayr)

  - Union

  - Implement multiple writable remotes (Max Sum)

  - Fix server-side copy (Max Sum)

  - Implement ListR (Max Sum)

  - Enable ListR when upstreams contain local (Max Sum)

  - WebDAV

  - Add support for --header-upload and --header-download
    (Tim Gallant)

  - Fix X-OC-Mtime header for Transip compatibility (Nick
    Craig-Wood)

  - Report full and consistent usage with about (Yves G)

  - Yandex

  - Add support for --header-upload and --header-download
    (Tim Gallant)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/rclone/passwordcheck"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected rclone packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rclone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rclone-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rclone-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rclone-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"rclone-1.53.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rclone-bash-completion-1.53.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rclone-debuginfo-1.53.3-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rclone-zsh-completion-1.53.3-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rclone / rclone-bash-completion / rclone-debuginfo / etc");
}