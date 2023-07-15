#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-a724cc7926.
#

include("compat.inc");

if (description)
{
  script_id(133117);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2019-5094", "CVE-2019-5188");
  script_xref(name:"FEDORA", value:"2020-a724cc7926");

  script_name(english:"Fedora 31 : e2fsprogs (2020-a724cc7926)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes

-----

A maliciously corrupted file systems can trigger buffer overruns in
the quota code used by e2fsck. (Addresses CVE-2019-5094)

E2fsck now checks to make sure the casefold flag is only set on
directories, and only when the casefold feature is enabled.

E2fsck will not disable the low dtime checks when using a backup
superblock where the last mount time is zero. This fixes a failure in
xfstests ext4/007.

Fix e2fsck so that when it needs to recreate the root directory, the
quota counts are correctly updated.

Fix e2scrub_all cron script so it checks to make sure e2scrub_all
exists, since the crontab and cron script might stick around after the
e2fsprogs package is removed. (Addresses Debian Bug: #932622)

Fix e2scrub_all so that it works when the free space is exactly the
snapshot size. (Addresses Debian Bug: #935009)

Avoid spurious lvm warnings when e2scrub_all is run out of cron on
non-systemd systems (Addresses Debian Bug: #940240)

Update the man pages to document the new fsverity feature, and improve
the documentation for the casefold and encrypt features.

E2fsck will no longer force a full file system check if time-based
forced checks are disabled and the last mount time or last write time
in the superblock are in the future.

Fix a potential out of bounds write when checking a maliciously
corrupted file system. This is probably not exploitable on 64-bit
platforms, but may be exploitable on 32-bit binaries depending on how
the compiler lays out the stack variables. (Addresses CVE-2019-5188)

Fixed spurious weekly e-mails when e2scrub_all is run via a cron job
on non-systemd systems. (Addresses Debian Bug: #944033)

Remove an unnecessary sleep in e2scrub which could add up to an
additional two second delay during the boot up. Also, avoid trying to
reap aborted snapshots if it has been disabled via e2scrub.conf.
(Addresses Debian Bug: #948193)

If a mischievous system administrator mounts a pseudo-file system such
as tmpfs with a device name that duplicates another mounted file
system, this could potentially confuse resize2fs when it needs to find
the mount point of a mounted file system. (Who would have guessed?)
Add some sanity checking so that we can make libext2fs more robust
against such insanity, at least on Linux. (GNU HURD doesn't support
st_rdev.)

Tune2fs now prohibits enabling or disabling uninit_bg if the file
system is mounted, since this could result in the file system getting
corrupted, and there is an unfortunate AskUbuntu article suggesting
this as a way to modify a file system's UUID on a live file system.
(Ext4 now has a way to do this safely, using the metadata_csum_seed
feature, which was added in the 4.4 Linux kernel.)

Fix potential crash in e2fsck when rebuilding very large directories
on file systems which have the new large_dir feature enable.

Fix support of 32-bit uid's and gid's in fuse2fs and in mke2fs -d.

Fix mke2fs's setting bad blocks to bigalloc file systems.

Fix a bug where fuse2fs would incorrectly report the i_blocks fields
for bigalloc file systems.

Resize2fs's minimum size estimates (via resize2fs -M) estimates are
now more accurate when run on mounted file systems.

Fixed potential memory leak in read_bitmap() in libext2fs.

Fixed various UBsan failures found when fuzzing file system images.
(Addresses Google Bug: #128130353)

Updated and clarified various man pages.

Performance, Internal Implementation, Development Support etc.

--------------------------------------------------------------

Fixed various debian packaging issues. (Addresses Debian Bug: #933247,
#932874, #932876, #932855, #932859, #932861, #932881, #932888)

Fix false positive test failure in f_pre_1970_date_encoding on 32-bit
systems with a 64-bit time_t. (Addresses Debian Bug: #932906)

Fixed various compiler warnings. (Addresses Google Bug #118836063)

Update the Czech, Dutch, French, German, Malay, Polish, Portuguese,
Spanish, Swedish, Ukrainian, and Vietnamese translations from the
Translation Project.

Speed up e2fsck on file systems with a very large number of inodes
caused by repeated calls to gettext().

The inode_io io_manager can now support files which are greater than
2GB.

The ext2_off_t and ext2_off64_t are now signed types so that
ext2fs_file_lseek() and ext2fs_file_llseek() can work correctly.

Reserve codepoint for the fast_commit feature.

Fixed various Debian packaging issues.

Fix portability problems for Illumous and on hurd/i386 (Addresses
Debian Bug: #944649)

Always compile the ext2fs_swap_* functions even on little-endian
architectures, so that debian/libext2fs.symbols can be consistent
across architectures.

Synchronized changes from Android's AOSP e2fsprogs tree.

Updated config.guess and config.sub with newer versions from the FSF.

Update the Chinese and Malay translations from the translation
project.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-a724cc7926"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected e2fsprogs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"e2fsprogs-1.45.5-1.fc31")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs");
}
