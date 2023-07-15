#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2273-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128504);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2019-13313");

  script_name(english:"SUSE SLES12 Security Update : libosinfo (SUSE-SU-2019:2273-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libosinfo fixes the following issues :

Security issue fixed :

CVE-2019-13313: Fixed a information leak where a local user could
gather credentials from the osinfo-install-script (bsc#1140749).

Non-security issues fixed: Fixed OS detection for multiple versions of
SLE12, SLE15 and openSUSE Leap (bsc#1105607, bsc#1122858, bsc#1105607,
bsc#1054986, bsc#1054986)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13313/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192273-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f732673e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-2273=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-2273=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libosinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libosinfo-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libosinfo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libosinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libosinfo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Libosinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libosinfo-0.2.12-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libosinfo-1_0-0-0.2.12-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libosinfo-1_0-0-debuginfo-0.2.12-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libosinfo-debuginfo-0.2.12-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libosinfo-debugsource-0.2.12-13.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"typelib-1_0-Libosinfo-1_0-0.2.12-13.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libosinfo");
}
