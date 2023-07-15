#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2298-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120074);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5156", "CVE-2018-5157", "CVE-2018-5158", "CVE-2018-5159", "CVE-2018-5168", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5188", "CVE-2018-6126");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2018:2298-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox to the 52.9 ESR release fixes the
following issues: These security issues were fixed :

  - Firefox ESR 52.9 :

  - CVE-2018-5188 Memory safety bugs fixed in Firefox 60,
    Firefox ESR 60.1, and Firefox ESR 52.9 (bsc#1098998).

  - CVE-2018-12368 No warning when opening executable
    SettingContent-ms files (bsc#1098998).

  - CVE-2018-12366 Invalid data handling during QCMS
    transformations (bsc#1098998).

  - CVE-2018-12365 Compromised IPC child process can list
    local filenames (bsc#1098998).

  - CVE-2018-12364 CSRF attacks through 307 redirects and
    NPAPI plugins (bsc#1098998).

  - CVE-2018-12363 Use-after-free when appending DOM nodes
    (bsc#1098998).

  - CVE-2018-12362 Integer overflow in SSSE3 scaler
    (bsc#1098998).

  - CVE-2018-12360 Use-after-free when using focus()
    (bsc#1098998).

  - CVE-2018-5156 Media recorder segmentation fault when
    track type is changed during capture (bsc#1098998).

  - CVE-2018-12359 Buffer overflow using computed size of
    canvas element (bsc#1098998).

  - Firefox ESR 52.8 :

  - CVE-2018-6126: Prevent heap buffer overflow in
    rasterizing paths in SVG with Skia (bsc#1096449).

  - CVE-2018-5183: Backport critical security fixes in Skia
    (bsc#1092548).

  - CVE-2018-5154: Use-after-free with SVG animations and
    clip paths (bsc#1092548).

  - CVE-2018-5155: Use-after-free with SVG animations and
    text paths (bsc#1092548).

  - CVE-2018-5157: Same-origin bypass of PDF Viewer to view
    protected PDF files (bsc#1092548).

  - CVE-2018-5158: Malicious PDF can inject JavaScript into
    PDF Viewer (bsc#1092548).

  - CVE-2018-5159: Integer overflow and out-of-bounds write
    in Skia (bsc#1092548).

  - CVE-2018-5168: Lightweight themes can be installed
    without user interaction (bsc#1092548).

  - CVE-2018-5178: Buffer overflow during UTF-8 to Unicode
    string conversion through legacy extension
    (bsc#1092548).

  - CVE-2018-5150: Memory safety bugs fixed in Firefox 60
    and Firefox ESR 52.8 (bsc#1092548).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12359/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12360/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12363/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12365/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12366/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12368/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5150/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5154/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5157/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5158/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5159/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5168/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5178/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5183/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5188/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6126/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182298-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?553f0fb5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-1536=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12368");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-devel-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debuginfo-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-debugsource-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-common-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"MozillaFirefox-translations-other-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"MozillaFirefox-devel-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debuginfo-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-debugsource-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-common-52.9.0esr-3.7.12")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"MozillaFirefox-translations-other-52.9.0esr-3.7.12")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
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
