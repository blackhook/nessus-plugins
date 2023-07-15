#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3718-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143633);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-15436",
    "CVE-2020-15437",
    "CVE-2020-25669",
    "CVE-2020-27777",
    "CVE-2020-28915",
    "CVE-2020-28974",
    "CVE-2020-29371"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2020:3718-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
which could have allowed local users to gain privileges or cause a
denial of service (bsc#1179141).

CVE-2020-15437: Fixed a NULL pointer dereference which could have
allowed local users to cause a denial of service(bsc#1179140).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
(bsc#1178182).

CVE-2020-27777: Restrict RTAS requests from userspace (bsc#1179107).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
have been used by local attackers to read privileged information or
potentially crash the kernel (bsc#1178589).

CVE-2020-29371: Fixed uninitialized memory leaks to userspace
(bsc#1179429).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1050549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1067665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1111666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15436/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15437/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25669/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27777/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28915/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28974/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29371/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203718-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8809a5f5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP1-2020-3718=1

SUSE Linux Enterprise Module for Live Patching 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP1-2020-3718=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP1-2020-3718=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-3718=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3718=1

SUSE Linux Enterprise High Availability 15-SP1 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP1-2020-3718=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27777");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-25669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-syms-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.75.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-syms-4.12.14-197.75.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
