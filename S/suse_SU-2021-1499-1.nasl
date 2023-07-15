#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1499-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149278);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-1871"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"SUSE SLES15 Security Update : webkit2gtk3 (SUSE-SU-2021:1499-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for webkit2gtk3 fixes the following issues :

Update to version 2.32.0 (bsc#1184155) :

  - Fix the authentication request port when URL omits the
    port.

  - Fix iframe scrolling when main frame is scrolled in
    async

  - scrolling mode.

  - Stop using g_memdup.

  - Show a warning message when overriding signal handler
    for

  - threading suspension.

  - Fix the build on RISC-V with GCC 11.

  - Fix several crashes and rendering issues.

  - Security fixes: CVE-2021-1788, CVE-2021-1844,
    CVE-2021-1871

Update in version 2.30.6 (bsc#1184262) :

  - Update user agent quirks again for Google Docs and
    Google Drive.

  - Fix several crashes and rendering issues.

  - Security fixes: CVE-2020-27918, CVE-2020-29623,
    CVE-2021-1765 CVE-2021-1789, CVE-2021-1799,
    CVE-2021-1801, CVE-2021-1870.

Update _constraints for armv6/armv7 (bsc#1182719)

restore NPAPI plugin support which was removed in 2.32.0

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1184262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27918/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29623/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1765/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1788/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1789/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1799/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1801/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1844/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1870/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-1871/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211499-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27fa17e4");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-1499=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-1499=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-1499=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-1499=1

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-1499=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-1499=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-1499=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-1499=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-1499=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-1499=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1499=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-1499=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-1499=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/05");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"libjavascriptcoregtk-4_0-18-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwebkit2gtk-4_0-37-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwebkit2gtk-4_0-37-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-JavaScriptCore-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-WebKit2-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"webkit2gtk-4_0-injected-bundles-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"webkit2gtk3-debugsource-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"webkit2gtk3-devel-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libjavascriptcoregtk-4_0-18-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwebkit2gtk-4_0-37-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libwebkit2gtk-4_0-37-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"typelib-1_0-JavaScriptCore-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"typelib-1_0-WebKit2-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"webkit2gtk-4_0-injected-bundles-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"webkit2gtk3-debugsource-2.32.0-3.74.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"webkit2gtk3-devel-2.32.0-3.74.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkit2gtk3");
}
