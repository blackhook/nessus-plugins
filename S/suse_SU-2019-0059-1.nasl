#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0059-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(121093);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-4191", "CVE-2018-4197", "CVE-2018-4207", "CVE-2018-4208", "CVE-2018-4209", "CVE-2018-4210", "CVE-2018-4212", "CVE-2018-4213", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263", "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4266", "CVE-2018-4267", "CVE-2018-4270", "CVE-2018-4272", "CVE-2018-4273", "CVE-2018-4278", "CVE-2018-4284", "CVE-2018-4299", "CVE-2018-4306", "CVE-2018-4309", "CVE-2018-4312", "CVE-2018-4314", "CVE-2018-4315", "CVE-2018-4316", "CVE-2018-4317", "CVE-2018-4318", "CVE-2018-4319", "CVE-2018-4323", "CVE-2018-4328", "CVE-2018-4345", "CVE-2018-4358", "CVE-2018-4359", "CVE-2018-4361", "CVE-2018-4372", "CVE-2018-4373", "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4378", "CVE-2018-4382", "CVE-2018-4386", "CVE-2018-4392", "CVE-2018-4416");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : webkit2gtk3 (SUSE-SU-2019:0059-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for webkit2gtk3 to version 2.22.4 fixes the following
issues :

Security issues fixed :

CVE-2018-4191, CVE-2018-4197, CVE-2018-4299, CVE-2018-4306,
CVE-2018-4309, CVE-2018-4392, CVE-2018-4312, CVE-2018-4314,
CVE-2018-4315, CVE-2018-4316, CVE-2018-4317, CVE-2018-4318,
CVE-2018-4319, CVE-2018-4323, CVE-2018-4328, CVE-2018-4358,
CVE-2018-4359, CVE-2018-4361, CVE-2018-4345, CVE-2018-4372,
CVE-2018-4373, CVE-2018-4375, CVE-2018-4376, CVE-2018-4416,
CVE-2018-4378, CVE-2018-4382, CVE-2018-4386 (bsc#1110279,
bsc#1116998).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1110279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4191/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4197/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4207/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4208/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4209/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4210/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4212/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4213/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4261/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4262/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4263/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4264/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4265/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4266/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4267/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4270/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4272/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4273/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4278/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4284/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4299/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4306/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4312/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4314/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4315/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4316/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4317/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4318/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4319/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4323/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4328/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4345/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4358/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4359/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4361/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4372/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4373/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4375/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4376/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4378/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4382/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4386/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4392/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-4416/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190059-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?987bc725"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-59=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-59=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2019-59=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-59=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-59=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-59=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-59=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-59=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-59=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-59=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-59=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-59=1

SUSE Enterprise Storage 4:zypper in -t patch SUSE-Storage-4-2019-59=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libjavascriptcoregtk-4_0-18-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebkit2gtk-4_0-37-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-WebKit2-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk-4_0-injected-bundles-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"webkit2gtk3-debugsource-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"typelib-1_0-WebKit2-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"webkit2gtk3-debugsource-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"typelib-1_0-WebKit2-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"webkit2gtk3-debugsource-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-WebKit2-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"webkit2gtk3-debugsource-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-JavaScriptCore-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"typelib-1_0-WebKit2-4_0-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.22.4-2.29.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"webkit2gtk3-debugsource-2.22.4-2.29.3")) flag++;


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
