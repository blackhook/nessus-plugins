#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2075-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120064);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-11646", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : webkit2gtk3 (SUSE-SU-2018:2075-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for webkit2gtk3 to version 2.20.3 fixes the following
issues: These security issues were fixed :

  - CVE-2018-4190: An unspecified issue allowed remote
    attackers to obtain sensitive credential information
    that is transmitted during a CSS mask-image fetch
    (bsc#1097693).

  - CVE-2018-4199: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (buffer overflow and application crash) via a
    crafted website (bsc#1097693)

  - CVE-2018-4218: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website that triggers an @generatorState
    use-after-free (bsc#1097693)

  - CVE-2018-4222: An unspecified issue allowed remote
    attackers to execute arbitrary code via a crafted
    website that leverages a getWasmBufferFromValue
    out-of-bounds read during WebAssembly compilation
    (bsc#1097693)

  - CVE-2018-4232: An unspecified issue allowed remote
    attackers to overwrite cookies via a crafted website
    (bsc#1097693)

  - CVE-2018-4233: An unspecified issue allowed remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption and application crash) via a
    crafted website (bsc#1097693)

  - CVE-2018-11646: webkitFaviconDatabaseSetIconForPageURL
    and webkitFaviconDatabaseSetIconURLForPageURL mishandle
    an unset pageURL, leading to an application crash
    (bsc#1095611).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11646/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4190/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4199/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4218/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4222/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4232/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4233/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182075-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fc09758"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-1401=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1401=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Proxy Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/26");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"libjavascriptcoregtk-4_0-18-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwebkit2gtk-4_0-37-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-JavaScriptCore-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-WebKit2-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"webkit2gtk-4_0-injected-bundles-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"webkit2gtk3-debugsource-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"webkit2gtk3-devel-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjavascriptcoregtk-4_0-18-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwebkit2gtk-4_0-37-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwebkit2gtk-4_0-37-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-JavaScriptCore-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-WebKit2-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"webkit2gtk-4_0-injected-bundles-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"webkit2gtk3-debugsource-2.20.3-3.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"webkit2gtk3-devel-2.20.3-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkit2gtk3");
}
