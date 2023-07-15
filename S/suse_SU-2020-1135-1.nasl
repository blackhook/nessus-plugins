#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1135-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(136082);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-8625",
    "CVE-2019-8710",
    "CVE-2019-8720",
    "CVE-2019-8743",
    "CVE-2019-8764",
    "CVE-2019-8766",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868",
    "CVE-2020-10018",
    "CVE-2020-11793"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"SUSE SLES12 Security Update : webkit2gtk3 (SUSE-SU-2020:1135-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for webkit2gtk3 to version 2.28.1 fixes the following
issues :

Security issues fixed :

CVE-2020-10018: Fixed a denial of service because the
m_deferredFocusedNodeChange data structure was mishandled
(bsc#1165528).

CVE-2020-11793: Fixed a potential arbitrary code execution caused by a
use-after-free vulnerability (bsc#1169658).

CVE-2019-8835: Fixed multiple memory corruption issues (bsc#1161719).

CVE-2019-8844: Fixed multiple memory corruption issues (bsc#1161719).

CVE-2019-8846: Fixed a use-after-free issue (bsc#1161719).

CVE-2020-3862: Fixed a memory handling issue (bsc#1163809).

CVE-2020-3867: Fixed an XSS issue (bsc#1163809).

CVE-2020-3868: Fixed multiple memory corruption issues that could have
lead to arbitrary code execution (bsc#1163809).

CVE-2020-3864,CVE-2020-3865: Fixed logic issues in the DOM object
context handling (bsc#1163809).

Non-security issues fixed: Add API to enable Process Swap on
(Cross-site) Navigation.

Add user messages API for the communication with the web extension.

Add support for same-site cookies.

Service workers are enabled by default.

Add support for Pointer Lock API.

Add flatpak sandbox support.

Make ondemand hardware acceleration policy never leave accelerated
compositing mode.

Always use a light theme for rendering form controls.

Add about:gpu to show information about the graphics stack.

Fixed issues while trying to play a video on NextCloud.

Fixed vertical alignment of text containing arabic diacritics.

Fixed build with icu 65.1.

Fixed page loading errors with websites using HSTS.

Fixed web process crash when displaying a KaTeX formula.

Fixed several crashes and rendering issues.

Switched to a single web process for Evolution and geary
(bsc#1159329).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1161719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1163809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1165528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8625/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8710/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8720/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8743/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8764/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8766/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8769/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8771/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8782/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8783/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8808/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8811/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8812/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8813/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8814/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8815/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8816/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8819/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8820/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8823/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8835/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8844/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8846/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10018/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11793/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3862/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3864/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3865/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3867/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3868/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201135-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?718c807f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-1135=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-1135=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-1135=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2020-1135=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2020-1135=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2020-1135=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-1135=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-1135=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2020-1135=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-1135=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-1135=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-1135=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-1135=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-1135=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2020-1135=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-1135=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3868");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10018");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libjavascriptcoregtk-4_0-18-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebkit2gtk-4_0-37-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebkit2gtk-4_0-37-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-JavaScriptCore-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-WebKit2-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk-4_0-injected-bundles-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk3-debugsource-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-JavaScriptCore-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-WebKit2-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk3-debugsource-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-JavaScriptCore-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-debugsource-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-devel-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libjavascriptcoregtk-4_0-18-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebkit2gtk-4_0-37-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebkit2gtk-4_0-37-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"typelib-1_0-JavaScriptCore-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"typelib-1_0-WebKit2-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"webkit2gtk-4_0-injected-bundles-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.28.1-2.50.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"webkit2gtk3-debugsource-2.28.1-2.50.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkit2gtk3");
}
