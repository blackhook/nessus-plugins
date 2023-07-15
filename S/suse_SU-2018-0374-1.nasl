#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0374-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106654);
  script_version("3.9");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2018-5089", "CVE-2018-5091", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5117");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox (SUSE-SU-2018:0374-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox to version 52.6 several issues. These
security issues were fixed :

  - CVE-2018-5091: Use-after-free with DTMF timers
    (bsc#1077291).

  - CVE-2018-5095: Integer overflow in Skia library during
    edge builder allocation (bsc#1077291).

  - CVE-2018-5096: Use-after-free while editing form
    elements (bsc#1077291).

  - CVE-2018-5097: Use-after-free when source document is
    manipulated during XSLT (bsc#1077291).

  - CVE-2018-5098: Use-after-free while manipulating form
    input elements (bsc#1077291).

  - CVE-2018-5099: Use-after-free with widget listener
    (bsc#1077291).

  - CVE-2018-5104: Use-after-free during font face
    manipulation (bsc#1077291).

  - CVE-2018-5089: Fixed several memory safety bugs
    (bsc#1077291).

  - CVE-2018-5117: URL spoofing with right-to-left text
    aligned left-to-right (bsc#1077291).

  - CVE-2018-5102: Use-after-free in HTML media elements
    (bsc#1077291).

  - CVE-2018-5103: Use-after-free during mouse event
    handling (bsc#1077291).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5089/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5091/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5095/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5096/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5097/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5098/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5099/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5102/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5103/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5104/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5117/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180374-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?babf11be"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2018-263=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-263=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-263=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-263=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-263=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-263=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-263=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-263=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-263=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-263=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-263=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-devel-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-devel-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.6.0esr-109.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-52.6.0esr-109.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
