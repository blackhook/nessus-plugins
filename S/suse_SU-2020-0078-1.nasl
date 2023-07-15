#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0078-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(132921);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-17015",
    "CVE-2019-17016",
    "CVE-2019-17017",
    "CVE-2019-17021",
    "CVE-2019-17022",
    "CVE-2019-17024",
    "CVE-2019-17026"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2020:0078-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for MozillaFirefox fixes the following issues :

Firefox Extended Support Release 68.4.1 ESR

  - Fixed: Security fix MFSA 2020-03 (bsc#1160498)

  - CVE-2019-17026 (bmo#1607443) IonMonkey type confusion
    with StoreElementHole and FallibleStoreElement

Firefox Extended Support Release 68.4.0 ESR

  - Fixed: Various security fixes MFSA 2020-02 (bsc#1160305)

  - CVE-2019-17015 (bmo#1599005) Memory corruption in parent
    process during new content process initialization on
    Windows

  - CVE-2019-17016 (bmo#1599181) Bypass of @namespace CSS
    sanitization during pasting

  - CVE-2019-17017 (bmo#1603055) Type Confusion in
    XPCVariant.cpp

  - CVE-2019-17021 (bmo#1599008) Heap address disclosure in
    parent process during content process initialization on
    Windows

  - CVE-2019-17022 (bmo#1602843) CSS sanitization does not
    escape HTML tags

  - CVE-2019-17024 (bmo#1507180, bmo#1595470, bmo#1598605,
    bmo#1601826) Memory safety bugs fixed in Firefox 72 and
    Firefox ESR 68.4

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17015/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17016/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17017/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17021/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17022/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17024/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17026/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200078-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b336c2fd");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-78=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2020-78=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-78=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2020-78=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17026");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
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

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debuginfo-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-debugsource-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-common-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"MozillaFirefox-translations-other-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-branding-upstream-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debuginfo-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-debugsource-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-common-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"MozillaFirefox-translations-other-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-branding-upstream-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-devel-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-68.4.1-3.66.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-68.4.1-3.66.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
