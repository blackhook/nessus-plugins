#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2345-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(129844);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2019-8595", "CVE-2019-8607", "CVE-2019-8615", "CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690");

  script_name(english:"SUSE SLES12 Security Update : webkit2gtk3 (SUSE-SU-2019:2345-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for webkit2gtk3 fixes the following issues :

Updated to version 2.24.4 (bsc#1148931).

Security issues fixed :

CVE-2019-8644, CVE-2019-8649, CVE-2019-8658, CVE-2019-8669,
CVE-2019-8678, CVE-2019-8680, CVE-2019-8683, CVE-2019-8684,
CVE-2019-8688, CVE-2019-8595, CVE-2019-8607, CVE-2019-8615,
CVE-2019-8644, CVE-2019-8649, CVE-2019-8658, CVE-2019-8666,
CVE-2019-8669, CVE-2019-8671, CVE-2019-8672, CVE-2019-8673,
CVE-2019-8676, CVE-2019-8677, CVE-2019-8678, CVE-2019-8679,
CVE-2019-8680, CVE-2019-8681, CVE-2019-8683, CVE-2019-8684,
CVE-2019-8686, CVE-2019-8687, CVE-2019-8688, CVE-2019-8689,
CVE-2019-8690

Non-security issues fixed: Improved loading of multimedia streams to
avoid memory exhaustion due to excessive caching.

Updated the user agent string to make happy certain websites which
would claim that the browser being used was unsupported.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1148931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8595/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8607/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8615/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8644/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8649/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8666/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8669/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8671/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8673/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8676/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8677/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8678/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8679/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8680/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8681/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8684/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8686/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8687/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8688/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8689/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8690/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192345-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b835ebc2"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2345=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2345=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2345=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2345=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2345=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2345=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2345=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2345=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2345=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2345=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2345=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2345=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8689");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/14");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-JavaScriptCore-4_0-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-WebKit2-4_0-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk3-debugsource-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-JavaScriptCore-4_0-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2-4_0-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-debugsource-2.24.4-2.47.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-devel-2.24.4-2.47.1")) flag++;


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
