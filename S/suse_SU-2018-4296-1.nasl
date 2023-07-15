#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4296-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(119955);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2015-2775", "CVE-2016-6893", "CVE-2018-0618", "CVE-2018-13796", "CVE-2018-5950");
  script_bugtraq_id(73922);

  script_name(english:"SUSE SLES12 Security Update : mailman (SUSE-SU-2018:4296-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mailman fixes the following security vulnerabilities :

Fixed a XSS vulnerability and information leak in user options CGI,
which could be used to execute arbitrary scripts in the user's browser
via specially encoded URLs (bsc#1077358 CVE-2018-5950)

Fixed a directory traversal vulnerability in MTA transports when using
the recommended Mailman Transport for Exim (bsc#925502 CVE-2015-2775)

Fixed a XSS vulnerability, which allowed malicious listowners to
inject scripts into the listinfo pages (bsc#1099510 CVE-2018-0618)

Fixed arbitrary text injection vulnerability in several mailman CGIs
(CVE-2018-13796 bsc#1101288)

Fixed a CSRF vulnerability on the user options page (CVE-2016-6893
bsc#995352)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1099510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2775/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6893/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-0618/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-13796/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5950/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184296-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8457595a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-3062=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-3062=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-3062=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2018-3062=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-3062=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-3062=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-3062=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-3062=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-3062=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-3062=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mailman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mailman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mailman-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"mailman-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mailman-debuginfo-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mailman-debugsource-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mailman-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mailman-debuginfo-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"mailman-debugsource-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mailman-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mailman-debuginfo-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mailman-debugsource-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mailman-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mailman-debuginfo-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"mailman-debugsource-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mailman-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mailman-debuginfo-2.1.17-3.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"mailman-debugsource-2.1.17-3.3.3")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailman");
}
