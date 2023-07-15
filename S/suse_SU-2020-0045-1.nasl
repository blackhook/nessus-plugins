#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0045-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(132745);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-1348",
    "CVE-2019-1349",
    "CVE-2019-1350",
    "CVE-2019-1351",
    "CVE-2019-1352",
    "CVE-2019-1353",
    "CVE-2019-1354",
    "CVE-2019-1387",
    "CVE-2019-19604"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : git (SUSE-SU-2020:0045-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for git fixes the following issues :

Security issues fixed :

CVE-2019-1349: Fixed issue on Windows, when submodules are cloned
recursively, under certain circumstances Git could be fooled into
using the same Git directory twice (bsc#1158787).

CVE-2019-19604: Fixed a recursive clone followed by a submodule update
could execute code contained within the repository without the user
explicitly having asked for that (bsc#1158795).

CVE-2019-1387: Fixed recursive clones that are currently affected by a
vulnerability that is caused by too-lax validation of submodule names,
allowing very targeted attacks via remote code execution in recursive
clones (bsc#1158793).

CVE-2019-1354: Fixed issue on Windows that refuses to write tracked
files with filenames that contain backslashes (bsc#1158792).

CVE-2019-1353: Fixed issue when run in the Windows Subsystem for Linux
while accessing a working directory on a regular Windows drive, none
of the NTFS protections were active (bsc#1158791).

CVE-2019-1352: Fixed issue on Windows was unaware of NTFS Alternate
Data Streams (bsc#1158790).

CVE-2019-1351: Fixed issue on Windows mistakes drive letters outside
of the US-English alphabet as relative paths (bsc#1158789).

CVE-2019-1350: Fixed incorrect quoting of command-line arguments
allowed remote code execution during a recursive clone in conjunction
with SSH URLs (bsc#1158788).

CVE-2019-1348: Fixed the --export-marks option of fast-import is
exposed also via the in-stream command feature export-marks=... and it
allows overwriting arbitrary paths (bsc#1158785).

Fixes an issue where git send-email failed to authenticate with SMTP
server (bsc#1082023)

Bug fixes: Add zlib dependency, which used to be provided by
openssl-devel, so that package can compile successfully after openssl
upgrade to 1.1.1. (bsc#1149792).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1348/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1349/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1350/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1351/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1352/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1353/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1354/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1387/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19604/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200045-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e867966f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-45=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2020-45=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-45=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2020-45=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-45=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2020-45=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-arch-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-cvs-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debugsource-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-email-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-gui-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-p4-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-web-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gitk-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-arch-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-core-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-core-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-credential-gnome-keyring-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-credential-libsecret-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-credential-libsecret-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-cvs-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-daemon-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-daemon-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-debugsource-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-email-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-gui-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-p4-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-svn-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-svn-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"git-web-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gitk-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-arch-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-cvs-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debugsource-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-email-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-gui-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-p4-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-web-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gitk-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-arch-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-core-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-core-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-credential-gnome-keyring-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-credential-gnome-keyring-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-credential-libsecret-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-credential-libsecret-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-cvs-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-daemon-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-daemon-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-debugsource-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-email-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-gui-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-p4-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-svn-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-svn-debuginfo-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"git-web-2.16.4-3.17.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gitk-2.16.4-3.17.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
