#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4087-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120186);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284", "CVE-2018-19409", "CVE-2018-19475", "CVE-2018-19476", "CVE-2018-19477");
  script_xref(name:"IAVB", value:"2019-B-0081-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ghostscript (SUSE-SU-2018:4087-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ghostscript to version 9.26 fixes the following 
issues :

Security issues fixed :

CVE-2018-19475: Fixed bypass of an intended access restriction in
psi/zdevice2.c (bsc#1117327)

CVE-2018-19476: Fixed bypass of an intended access restriction in
psi/zicc.c (bsc#1117313)

CVE-2018-19477: Fixed bypass of an intended access restriction in
psi/zfjbig2.c (bsc#1117274)

CVE-2018-19409: Check if another device is used correctly in
LockSafetyParams (bsc#1117022)

CVE-2018-18284: Fixed potential sandbox escape through 1Policy
operator (bsc#1112229)

CVE-2018-18073: Fixed leaks through operator in saved execution stacks
(bsc#1111480)

CVE-2018-17961: Fixed a -dSAFER sandbox escape by bypassing
executeonly (bsc#1111479)

CVE-2018-17183: Fixed a potential code injection by specially crafted
PostScript files (bsc#1109105)

Version update to 9.26 (bsc#1117331): Security issues have been the
primary focus

Minor bug fixes and improvements

For release summary see: http://www.ghostscript.com/doc/9.26/News.htm

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.ghostscript.com/doc/9.26/News.htm
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ghostscript.com/doc/9.26/News.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17183/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17961/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18073/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18284/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19409/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19475/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19476/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19477/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184087-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1602a3db"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2914=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-2914=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2914=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspectre-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspectre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspectre1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libspectre1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-debuginfo-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-debugsource-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-devel-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-mini-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-mini-debuginfo-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-mini-debugsource-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-mini-devel-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-x11-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ghostscript-x11-debuginfo-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libspectre-debugsource-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libspectre-devel-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libspectre1-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libspectre1-debuginfo-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-debuginfo-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-debugsource-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-devel-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-mini-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-mini-debuginfo-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-mini-debugsource-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-mini-devel-9.26-3.9.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-x11-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ghostscript-x11-debuginfo-9.26-3.9.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libspectre-debugsource-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libspectre-devel-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libspectre1-0.2.8-3.4.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libspectre1-debuginfo-0.2.8-3.4.3")) flag++;


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
