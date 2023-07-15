#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2545-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(129583);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2019-9811",
    "CVE-2019-9812",
    "CVE-2019-11710",
    "CVE-2019-11714",
    "CVE-2019-11716",
    "CVE-2019-11718",
    "CVE-2019-11720",
    "CVE-2019-11721",
    "CVE-2019-11723",
    "CVE-2019-11724",
    "CVE-2019-11725",
    "CVE-2019-11727",
    "CVE-2019-11728",
    "CVE-2019-11733",
    "CVE-2019-11735",
    "CVE-2019-11736",
    "CVE-2019-11738",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11747",
    "CVE-2019-11748",
    "CVE-2019-11749",
    "CVE-2019-11750",
    "CVE-2019-11751",
    "CVE-2019-11752",
    "CVE-2019-11753"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2019:2545-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaFirefox to 68.1 fixes the following issues :

Security issues fixed :

CVE-2019-9811: Fixed a sandbox escape via installation of malicious
language pack. (bsc#1140868)

CVE-2019-9812: Fixed a sandbox escape through Firefox Sync.
(bsc#1149294)

CVE-2019-11710: Fixed several memory safety bugs. (bsc#1140868)

CVE-2019-11714: Fixed a potentially exploitable crash in Necko.
(bsc#1140868)

CVE-2019-11716: Fixed a sandbox bypass. (bsc#1140868)

CVE-2019-11718: Fixed inadequate sanitation in the Activity Stream
component. (bsc#1140868)

CVE-2019-11720: Fixed a character encoding XSS vulnerability.
(bsc#1140868)

CVE-2019-11721: Fixed a homograph domain spoofing issue through
unicode latin 'kra' character. (bsc#1140868)

CVE-2019-11723: Fixed a cookie leakage during add-on fetching across
private browsing boundaries. (bsc#1140868)

CVE-2019-11724: Fixed an outdated permission, granting access to
retired site input.mozilla.org. (bsc#1140868)

CVE-2019-11725: Fixed a Safebrowsing bypass involving WebSockets.
(bsc#1140868)

CVE-2019-11727: Fixed a vulnerability where it possible to force NSS
to sign CertificateVerify with PKCS#1 v1.5 signatures when those are
the only ones advertised by server in CertificateRequest in TLS 1.3.
(bsc#1141322)

CVE-2019-11728: Fixed an improper handling of the Alt-Svc header that
allowed remote port scans. (bsc#1140868)

CVE-2019-11733: Fixed an insufficient protection of stored passwords
in 'Saved Logins'. (bnc#1145665)

CVE-2019-11735: Fixed several memory safety bugs. (bnc#1149293)

CVE-2019-11736: Fixed a file manipulation and privilege escalation in
Mozilla Maintenance Service. (bnc#1149292)

CVE-2019-11738: Fixed a content security policy bypass through
hash-based sources in directives. (bnc#1149302)

CVE-2019-11740: Fixed several memory safety bugs. (bsc#1149299)

CVE-2019-11742: Fixed a same-origin policy violation involving SVG
filters and canvas to steal cross-origin images. (bsc#1149303)

CVE-2019-11743: Fixed a timing side-channel attack on cross-origin
information, utilizing unload event attributes. (bsc#1149298)

CVE-2019-11744: Fixed an XSS caused by breaking out of title and
textarea elements using innerHTML. (bsc#1149304)

CVE-2019-11746: Fixed a use-after-free while manipulating video.
(bsc#1149297)

CVE-2019-11752: Fixed a use-after-free while extracting a key value in
IndexedDB. (bsc#1149296)

CVE-2019-11753: Fixed a privilege escalation with Mozilla Maintenance
Service in custom Firefox installation location. (bsc#1149295)

Non-security issues fixed: Latest update now also released for s390x.
(bsc#1109465)

Fixed a segmentation fault on s390vsl082. (bsc#1117473)

Fixed a crash on SLES15 s390x. (bsc#1124525)

Fixed a segmentation fault. (bsc#1133810)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1123482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1124525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1133810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1138688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11710/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11714/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11716/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11718/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11720/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11721/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11723/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11724/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11725/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11727/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11728/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11733/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11735/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11736/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11738/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11740/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11742/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11743/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11744/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11746/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11747/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11748/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11749/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11750/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11751/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11753/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9811/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9812/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192545-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55835179");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2545=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2545=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-2545=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2545=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-SLE-68-4.8.5")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debuginfo-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debugsource-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-common-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-other-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-SLE-68-4.8.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-SLE-68-4.8.5")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debuginfo-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debugsource-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-common-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-other-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-SLE-68-4.8.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-devel-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-68.1.0-3.54.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-68.1.0-3.54.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
