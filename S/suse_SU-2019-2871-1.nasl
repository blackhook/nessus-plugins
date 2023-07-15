#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2871-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130449);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox, MozillaFirefox-branding-SLE (SUSE-SU-2019:2871-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox, MozillaFirefox-branding-SLE fixes the
following issues :

Changes in MozillaFirefox :

Security issues fixed :

CVE-2019-15903: Fixed a heap overflow in the expat library
(bsc#1149429).

CVE-2019-11757: Fixed a use-after-free when creating index
updates in IndexedDB (bsc#1154738).

CVE-2019-11758: Fixed a potentially exploitable crash due to
360 Total Security (bsc#1154738).

CVE-2019-11759: Fixed a stack-based buffer overflow in HKDF
output (bsc#1154738).

CVE-2019-11760: Fixed a stack-based buffer overflow in
WebRTC networking (bsc#1154738).

CVE-2019-11761: Fixed an unintended access to a privileged
JSONView object (bsc#1154738).

CVE-2019-11762: Fixed a same-origin-property violation
(bsc#1154738).

CVE-2019-11763: Fixed an XSS bypass (bsc#1154738).

CVE-2019-11764: Fixed several memory safety bugs
(bsc#1154738).

Non-security issues fixed: Added Provides-line for translations-common
(bsc#1153423) .

Moved some settings from branding-package here (bsc#1153869).

Disabled DoH by default.

Changes in MozillaFirefox-branding-SLE: Moved extensions preferences
to core package (bsc#1153869).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1129528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11757/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11758/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11759/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11760/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11761/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11762/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11763/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11764/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15903/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192871-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fce15959"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2871=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2871=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-2871=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2871=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11764");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/01");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-SLE-68-4.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debuginfo-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debugsource-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-common-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-other-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-SLE-68-4.11.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-SLE-68-4.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debuginfo-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debugsource-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-common-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-other-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-SLE-68-4.11.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-devel-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-68.2.0-3.59.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-68.2.0-3.59.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-SLE");
}
