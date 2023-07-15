#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0241-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(145739);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id("CVE-2020-26976", "CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23960", "CVE-2021-23964");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2021:0241-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox fixes the following issues :

Firefox Extended Support Release 78.7.0 ESR (MFSA 2021-04,
bsc#1181414)

  - CVE-2021-23953: Fixed a Cross-origin information leakage
    via redirected PDF requests

  - CVE-2021-23954: Fixed a type confusion when using
    logical assignment operators in JavaScript switch
    statements

  - CVE-2020-26976: Fixed an issue where HTTPS pages could
    have been intercepted by a registered service worker
    when they should not have been

  - CVE-2021-23960: Fixed a use-after-poison for incorrectly
    redeclared JavaScript variables during GC

  - CVE-2021-23964: Fixed Memory safety bugs

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1181414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-26976/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-23953/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-23954/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-23960/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-23964/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210241-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?665af26b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-241=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2021-241=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-241=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2021-241=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2021-241=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-241=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-241=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2021-241=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2021-241=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-241=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-241=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2021-241=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2021-241=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2021-241=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2021-241=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2021-241=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2021-241=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23964");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debuginfo-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-debugsource-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-devel-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"MozillaFirefox-translations-common-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debuginfo-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debugsource-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-devel-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-translations-common-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debuginfo-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debugsource-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-devel-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-translations-common-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-debuginfo-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-debugsource-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-devel-78.7.0-112.45.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"MozillaFirefox-translations-common-78.7.0-112.45.1")) flag++;


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
