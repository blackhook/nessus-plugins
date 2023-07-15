#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1094-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(148387);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id("CVE-2021-21261");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : flatpak, libostree, xdg-desktop-portal, xdg-desktop-portal-gtk (SUSE-SU-2021:1094-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for flatpak, libostree, xdg-desktop-portal,
xdg-desktop-portal-gtk fixes the following issues :

libostree :

Update to version 2020.8

Enable LTO. (bsc#1133120)

This update contains scalability improvements and bugfixes.

Caching-related HTTP headers are now supported on summaries and
signatures, so that they do not have to be re-downloaded if not
changed in the meanwhile.

Summaries and delta have been reworked to allow more fine-grained
fetching.

Fixes several bugs related to atomic variables, HTTP timeouts, and
32-bit architectures.

Static deltas can now be signed to more easily support offline
verification.

There's now support for multiple initramfs images; Is it possible to
have a 'main' initramfs image and a secondary one which represents
local configuration.

The documentation is now moved to https://ostreedev.github.io/ostree/

Fix for an assertion failure when upgrading from systems before ostree
supported devicetree.

ostree no longer hardlinks zero sized files to avoid hitting
filesystem maximum link counts.

ostree now supports `/` and `/boot` being on the same filesystem.

Improvements to the GObject Introspection metadata, some (cosmetic)
static analyzer fixes, a fix for the immutable bit on s390x, dropping
a deprecated bit in the systemd unit file.

Fix a regression 2020.4 where the 'readonly sysroot' changes
incorrectly left the sysroot read-only on systems that started out
with a read-only `/` (most of them, e.g. Fedora Silverblue/IoT at
least).

The default dracut config now enables reproducibility.

There is a new ostree admin unlock `--transient`. This should to be a
foundation for further support for 'live' updates.

New `ed25519` signing support, powered by `libsodium`.

stree commit gained a new `--base` argument, which significantly
simplifies constructing 'derived' commits, particularly for systems
using SELinux.

Handling of the read-only sysroot was reimplemented to run in the
initramfs and be more reliable. Enabling the `readonly=true` flag in
the repo config is recommended.

Several fixes in locking for the temporary 'staging' directories
OSTree creates, particularly on NFS.

A new `timestamp-check-from-rev` option was added for pulls, which
makes downgrade protection more reliable and will be used by Fedora
CoreOS.

Several fixes and enhancements made for 'collection' pulls including a
new `--mirror` option.

The ostree commit command learned a new `--mode-ro-executables` which
enforces `W^R` semantics on all executables.

Added a new commit metadata key `OSTREE_COMMIT_META_KEY_ARCHITECTURE`
to help standardize the architecture of the OSTree commit. This could
be used on the client side for example to sanity-check that the commit
matches the architecture of the machine before deploying.

Stop invalid usage of `%_libexecdir` :

  + Use `%{_prefix}/lib` where appropriate.

  + Use `_systemdgeneratordir` for the systemd-generators.

  + Define `_dracutmodulesdir` based on `dracut.pc`. Add
    BuildRequires(dracut) for this to work.

xdg-desktop-portal :

Update to version 1.8.0 :

Ensure systemd rpm macros are called at install/uninstall times for
systemd user services.

Add BuildRequires on systemd-rpm-macros.

openuri :

  - Allow skipping the chooser for more URL tyles

  - Robustness fixes

filechooser :

  - Return the current filter

  - Add a 'directory' option

  - Document the 'writable' option

camera :

  - Make the client node visible

  - Don't leak pipewire proxy

Fix file descriptor leaks

Testsuite improvements

Updated translations.

document :

  - Reduce the use of open fds

  - Add more tests and fix issues they found

  - Expose directories with their proper name

  - Support exporting directories

  - New fuse implementation

background: Avoid a segfault

screencast: Require pipewire 0.3

Better support for snap and toolbox

Require `/usr/bin/fusermount`: `xdg-document-portal` calls out to the
binary. (bsc#1175899) Without it, files or dirs can be selected, but
whatever is done with or in them, will not have any effect

Fixes for `%_libexecdir` changing to `/usr/libexec`

xdg-desktop-portal-gtk :

Update to version 1.8.0 :

filechooser :

  - Return the current filter

  - Handle the 'directory' option to select directories

  - Only show preview when we have an image

screenshot: Fix cancellation

appchooser: Avoid a crash

wallpaper :

  - Properly preview placement settings

  - Drop the lockscreen option

printing: Improve the notification

Updated translations.

settings: Fall back to gsettings for enable-animations

screencast: Support Mutter version to 3 (New pipewire api ver 3).

flatpak :

Update to version 1.10.2 (jsc#SLE-17238, ECO-3148)

This is a security update which fixes a potential attack
where a flatpak application could use custom formated
`.desktop` file to gain access to files on the host system.

Fix memory leaks

Documentation and translations updates

Spawn portal better handles non-utf8 filenames

Fix flatpak build on systems with setuid bwrap

Fix crash on updating apps with no deploy data

Remove deprecated texinfo packaging macros.

Support for the new repo format which should make updates faster and
download less data.

The systemd generator snippets now call flatpak `--print-updated-env`
in place of a bunch of shell for better login performance.

The `.profile` snippets now disable GVfs when calling flatpak to avoid
spawning a gvfs daemon when logging in via ssh.

Flatpak now finds the pulseaudio sockets better in uncommon
configurations.

Sandboxes with network access it now also has access to the
`systemd-resolved` socket to do dns lookups.

Flatpak supports unsetting environment variables in the sandbox using
`--unset-env`, and `--env=FOO=` now sets FOO to the empty string
instead of unsetting it.

The spawn portal now has an option to share the pid namespace with the
sub-sandbox.

This security update fixes a sandbox escape where a malicious
application can execute code outside the sandbox by controlling the
environment of the 'flatpak run' command when spawning a sub-sandbox
(bsc#1180996, CVE-2021-21261)

Fix support for ppc64.

Move flatpak-bisect and flatpak-coredumpctl to devel subpackage, allow
to remove python3 dependency on main package.

Enable LTO as gobject-introspection works fine with LTO. (bsc#1133124)

Fixed progress reporting for OCI and extra-data.

The in-memory summary cache is more efficient.

Fixed authentication getting stuck in a loop in some cases.

Fixed authentication error reporting.

Extract OCI info for runtimes as well as apps.

Fixed crash if anonymous authentication fails and `-y` is specified.

flatpak info now only looks at the specified installation if one is
specified.

Better error reporting for server HTTP errors during download.

Uninstall now removes applications before the runtime it depends on.

Avoid updating metadata from the remote when uninstalling.

FlatpakTransaction now verifies all passed in refs to avoid.

Added validation of collection id settings for remotes.

Fix seccomp filters on s390.

Robustness fixes to the spawn portal.

Fix support for masking update in the system installation.

Better support for distros with uncommon models of merged `/usr`.

Cache responses from localed/AccountService.

Fix hangs in cases where `xdg-dbus-proxy` fails to start.

Fix double-free in cups socket detection.

OCI authenticator now doesn't ask for auth in case of http errors.

Fix invalid usage of `%{_libexecdir}` to reference systemd
directories.

Fixes for `%_libexecdir` changing to `/usr/libexec`

Avoid calling authenticator in update if ref didn't change

Don't fail transaction if ref is already installed (after transaction
start)

Fix flatpak run handling of userns in the `--device=all` case

Fix handling of extensions from different remotes

Fix flatpak run `--no-session-bus`

`FlatpakTransaction` has a new signal `install-authenticator` which
clients can handle to install authenticators needed for the
transaction. This is done in the CLI commands.

Now the host timezone data is always exposed, fixing several apps that
had timezone issues.

There's a new systemd unit (not installed by default) to automatically
detect plugged in usb sticks with sideload repos.

By default the `gdm env.d` file is no longer installed because the
systemd generators work better.

`create-usb` now exports partial commits by default

Fix handling of docker media types in oci remotes

Fix subjects in `remote-info --log` output

This release is also able to host flatpak images on e.g. docker hub.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1175899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ostreedev.github.io/ostree/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-21261/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211094-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a97906e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP2-2021-1094=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1094=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree-1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libostree-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:system-user-flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-OSTree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xdg-desktop-portal-gtk-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"flatpak-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"flatpak-debuginfo-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"flatpak-debugsource-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"flatpak-devel-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"flatpak-zsh-completion-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libflatpak0-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libflatpak0-debuginfo-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-1-1-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-1-1-debuginfo-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-debuginfo-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-debugsource-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libostree-devel-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"system-user-flatpak-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"typelib-1_0-Flatpak-1_0-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"typelib-1_0-OSTree-1_0-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-debuginfo-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-debugsource-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-devel-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-gtk-1.8.0-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-gtk-debuginfo-1.8.0-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"xdg-desktop-portal-gtk-debugsource-1.8.0-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"flatpak-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"flatpak-debuginfo-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"flatpak-debugsource-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"flatpak-devel-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"flatpak-zsh-completion-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libflatpak0-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libflatpak0-debuginfo-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-1-1-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-1-1-debuginfo-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-debuginfo-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-debugsource-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libostree-devel-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"system-user-flatpak-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"typelib-1_0-Flatpak-1_0-1.10.2-4.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"typelib-1_0-OSTree-1_0-2020.8-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-debuginfo-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-debugsource-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-devel-1.8.0-5.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-gtk-1.8.0-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-gtk-debuginfo-1.8.0-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"xdg-desktop-portal-gtk-debugsource-1.8.0-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak / libostree / xdg-desktop-portal / xdg-desktop-portal-gtk");
}
