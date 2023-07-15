#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2975-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(117901);
  script_version("1.6");
  script_cvs_date("Date: 2019/09/10 13:51:49");

  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16510", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16543", "CVE-2018-16585", "CVE-2018-16802", "CVE-2018-17183");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ghostscript (SUSE-SU-2018:2975-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript to version 9.25 fixes the following 
issues :

These security issues were fixed :

CVE-2018-17183: Remote attackers were be able to supply crafted
PostScript to potentially overwrite or replace error handlers to
inject code (bsc#1109105)

CVE-2018-15909: Prevent type confusion using the .shfill operator that
could have been used by attackers able to supply crafted PostScript
files to crash the interpreter or potentially execute code
(bsc#1106172).

CVE-2018-15908: Prevent attackers that are able to supply malicious
PostScript files to bypass .tempfile restrictions and write files
(bsc#1106171).

CVE-2018-15910: Prevent a type confusion in the LockDistillerParams
parameter that could have been used to crash the interpreter or
execute code (bsc#1106173).

CVE-2018-15911: Prevent use uninitialized memory access in the
aesdecode operator that could have been used to crash the interpreter
or potentially execute code (bsc#1106195).

CVE-2018-16513: Prevent a type confusion in the setcolor function that
could have been used to crash the interpreter or possibly have
unspecified other impact (bsc#1107412).

CVE-2018-16509: Incorrect 'restoration of privilege' checking during
handling of /invalidaccess exceptions could be have been used by
attackers able to supply crafted PostScript to execute code using the
'pipe' instruction (bsc#1107410).

CVE-2018-16510: Incorrect exec stack handling in the 'CS' and 'SC' PDF
primitives could have been used by remote attackers able to supply
crafted PDFs to crash the interpreter or possibly have unspecified
other impact (bsc#1107411).

CVE-2018-16542: Prevent attackers able to supply crafted PostScript
files from using insufficient interpreter stack-size checking during
error handling to crash the interpreter (bsc#1107413).

CVE-2018-16541: Prevent attackers able to supply crafted PostScript
files from using incorrect free logic in pagedevice replacement to
crash the interpreter (bsc#1107421).

CVE-2018-16540: Prevent use-after-free in copydevice handling that
could have been used to crash the interpreter or possibly have
unspecified other impact (bsc#1107420).

CVE-2018-16539: Prevent attackers able to supply crafted PostScript
files from using incorrect access checking in temp file handling to
disclose contents of files on the system otherwise not readable
(bsc#1107422).

CVE-2018-16543: gssetresolution and gsgetresolution allowed attackers
to have an unspecified impact (bsc#1107423).

CVE-2018-16511: A type confusion in 'ztype' could have been used by
remote attackers able to supply crafted PostScript to crash the
interpreter or possibly have unspecified other impact (bsc#1107426).

CVE-2018-16585: The .setdistillerkeys PostScript command was accepted
even though it is not intended for use during document processing
(e.g., after the startup phase). This lead to memory corruption,
allowing remote attackers able to supply crafted PostScript to crash
the interpreter or possibly have unspecified other impact
(bsc#1107581).

CVE-2018-16802: Incorrect 'restoration of privilege' checking when
running out of stack during exception handling could have been used by
attackers able to supply crafted PostScript to execute code using the
'pipe' instruction. This is due to an incomplete fix for
CVE-2018-16509 (bsc#1108027).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15908/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15909/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15910/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16509/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16510/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16511/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16513/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16540/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16541/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16542/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16585/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16802/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17183/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182975-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d3f27e4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2121=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2121=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2121=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2121=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2121=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2121=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2121=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2121=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2121=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/03");
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
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"ghostscript-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ghostscript-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ghostscript-debugsource-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ghostscript-x11-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ghostscript-x11-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ghostscript-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ghostscript-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ghostscript-debugsource-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ghostscript-x11-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ghostscript-x11-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ghostscript-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ghostscript-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ghostscript-debugsource-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ghostscript-x11-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ghostscript-x11-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ghostscript-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ghostscript-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ghostscript-debugsource-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ghostscript-x11-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ghostscript-x11-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ghostscript-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ghostscript-debuginfo-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ghostscript-debugsource-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ghostscript-x11-9.25-23.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ghostscript-x11-debuginfo-9.25-23.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
