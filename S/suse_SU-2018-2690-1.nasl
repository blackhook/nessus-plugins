#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2690-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120097);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-9269", "CVE-2018-7685");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libzypp, zypper (SUSE-SU-2018:2690-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libzypp, zypper, libsolv provides the following 
fixes :

Security fixes in libzypp :

CVE-2018-7685: PackageProvider: Validate RPMs before caching
(bsc#1091624, bsc#1088705)

CVE-2017-9269: Be sure bad packages do not stay in the cache
(bsc#1045735)

Changes in libzypp: Update to version 17.6.4

Automatically fetch repository signing key from gpgkey url
(bsc#1088037)

lsof: use '-K i' if lsof supports it (bsc#1099847,bsc#1036304)

Check for not imported keys after multi key import from rpmdb
(bsc#1096217)

Flags: make it std=c++14 ready

Ignore /var, /tmp and /proc in zypper ps. (bsc#1096617)

Show GPGME version in log

Adapt to changes in libgpgme11-11.1.0 breaking the signature
verification (bsc#1100427)

RepoInfo::provideKey: add report telling where we look for missing
keys.

Support listing gpgkey URLs in repo files (bsc#1088037)

Add new report to request user approval for importing a package key

Handle http error 502 Bad Gateway in curl backend (bsc#1070851)

Add filesize check for downloads with known size (bsc#408814)

Removed superfluous space in translation (bsc#1102019)

Prevent the system from sleeping during a commit

RepoManager: Explicitly request repo2solv to generate application
pseudo packages.

libzypp-devel should not require cmake (bsc#1101349)

Avoid zombies from ExternalProgram

Update ApiConfig

HardLocksFile: Prevent against empty commit without Target having been
been loaded (bsc#1096803)

lsof: use '-K i' if lsof supports it (bsc#1099847)

Add filesize check for downloads with known size (bsc#408814)

Fix detection of metalink downloads and prevent aborting if a metalink
file is larger than the expected data file.

Require libsolv-devel >= 0.6.35 during build (fixing bsc#1100095)

Make use of %license macro (bsc#1082318)

Security fix in zypper: CVE-2017-9269: Improve signature check
callback messages (bsc#1045735)

Changes in zypper: Always set error status if any nr of unknown
repositories are passed to lr and ref (bsc#1093103)

Notify user about unsupported rpm V3 keys in an old rpm database
(bsc#1096217)

Detect read only filesystem on system modifying operations (fixes
#199)

Use %license (bsc#1082318)

Handle repo aliases containing multiple ':' in the PackageArgs parser
(bsc #1041178)

Fix broken display of detailed query results.

Fix broken search for items with a dash. (bsc#907538, bsc#1043166,
bsc#1070770)

Disable repository operations when searching installed packages.
(bsc#1084525)

Prevent nested calls to exit() if aborted by a signal. (bsc#1092413)

ansi.h: Prevent ESC sequence strings from going out of scope.
(bsc#1092413)

Fix some translation errors.

Support listing gpgkey URLs in repo files (bsc#1088037)

Check for root privileges in zypper verify and si (bsc#1058515)

XML <install-summary> attribute `packages-to-change` added
(bsc#1102429) </install-summary>

Add expert (allow-*) options to all installer commands (bsc#428822)

Sort search results by multiple columns (bsc#1066215)

man: Strengthen that `--config FILE' affects zypper.conf, not
zypp.conf (bsc#1100028)

Set error status if repositories passed to lr and ref are not known
(bsc#1093103)

Do not override table style in search

Fix out of bound read in MbsIterator

Add --supplements switch to search and info

Add setter functions for zypp cache related config values to ZConfig

Changes in libsolv: convert repo2solv.sh script into a binary tool

Make use of %license macro (bsc#1082318)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1058515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=408814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=428822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9269/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7685/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182690-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59f912e0"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2018-1883=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1883=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-debugsource-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-devel-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsolv-tools-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debuginfo-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-debugsource-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libzypp-devel-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"perl-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ruby-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-1.14.10-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debuginfo-1.14.10-3.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"zypper-debugsource-1.14.10-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-debugsource-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-devel-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsolv-tools-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debuginfo-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-debugsource-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libzypp-devel-17.6.4-3.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"perl-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ruby-solv-debuginfo-0.6.35-3.5.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-1.14.10-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debuginfo-1.14.10-3.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"zypper-debugsource-1.14.10-3.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / zypper");
}
