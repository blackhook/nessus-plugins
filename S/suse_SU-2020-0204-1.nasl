#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0204-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133202);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/27");

  script_cve_id("CVE-2019-14896", "CVE-2019-14897");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2020:0204-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the Linux Kernel 3.12.74-60_64_110 fixes several
issues.

The following security issues were fixed :

CVE-2019-14896: A heap-based buffer overflow vulnerability was found
in the Marvell WiFi chip driver. A remote attacker could cause a
denial of service (system crash) or, possibly execute arbitrary code,
when the lbs_ibss_join_existing function is called after a STA
connects to an AP (bsc#1157157).

CVE-2019-14897: A stack-based buffer overflow was found in the Marvell
WiFi chip driver. An attacker was able to cause a denial of service
(system crash) or, possibly execute arbitrary code, when a STA works
in IBSS mode (allows connecting stations together without the use of
an AP) and connects to another STA (bsc#1157155).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14896/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14897/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200204-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f532555c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-182=1
SUSE-SLE-SAP-12-SP3-2020-184=1 SUSE-SLE-SAP-12-SP3-2020-187=1
SUSE-SLE-SAP-12-SP3-2020-189=1 SUSE-SLE-SAP-12-SP3-2020-203=1
SUSE-SLE-SAP-12-SP3-2020-205=1 SUSE-SLE-SAP-12-SP3-2020-208=1
SUSE-SLE-SAP-12-SP3-2020-211=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-192=1
SUSE-SLE-SAP-12-SP2-2020-194=1 SUSE-SLE-SAP-12-SP2-2020-196=1
SUSE-SLE-SAP-12-SP2-2020-198=1 SUSE-SLE-SAP-12-SP2-2020-200=1
SUSE-SLE-SAP-12-SP2-2020-202=1 SUSE-SLE-SAP-12-SP2-2020-204=1

SUSE Linux Enterprise Server for SAP 12-SP1 :

zypper in -t patch SUSE-SLE-SAP-12-SP1-2020-206=1
SUSE-SLE-SAP-12-SP1-2020-207=1 SUSE-SLE-SAP-12-SP1-2020-209=1
SUSE-SLE-SAP-12-SP1-2020-210=1 SUSE-SLE-SAP-12-SP1-2020-212=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-182=1
SUSE-SLE-SERVER-12-SP3-2020-184=1 SUSE-SLE-SERVER-12-SP3-2020-187=1
SUSE-SLE-SERVER-12-SP3-2020-189=1 SUSE-SLE-SERVER-12-SP3-2020-203=1
SUSE-SLE-SERVER-12-SP3-2020-205=1 SUSE-SLE-SERVER-12-SP3-2020-208=1
SUSE-SLE-SERVER-12-SP3-2020-211=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-192=1
SUSE-SLE-SERVER-12-SP2-2020-194=1 SUSE-SLE-SERVER-12-SP2-2020-196=1
SUSE-SLE-SERVER-12-SP2-2020-198=1 SUSE-SLE-SERVER-12-SP2-2020-200=1
SUSE-SLE-SERVER-12-SP2-2020-202=1 SUSE-SLE-SERVER-12-SP2-2020-204=1

SUSE Linux Enterprise Server 12-SP1-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2020-206=1
SUSE-SLE-SERVER-12-SP1-2020-207=1 SUSE-SLE-SERVER-12-SP1-2020-209=1
SUSE-SLE-SERVER-12-SP1-2020-210=1 SUSE-SLE-SERVER-12-SP1-2020-212=1

SUSE Linux Enterprise Module for Live Patching 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP1-2020-161=1

SUSE Linux Enterprise Module for Live Patching 15 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-2020-170=1

SUSE Linux Enterprise Live Patching 12-SP5 :

zypper in -t patch SUSE-SLE-Live-Patching-12-SP5-2020-180=1
SUSE-SLE-Live-Patching-12-SP5-2020-181=1

SUSE Linux Enterprise Live Patching 12-SP4 :

zypper in -t patch SUSE-SLE-Live-Patching-12-SP4-2020-185=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_110-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_110-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_115-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_115-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_118-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_118-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_121-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_121-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_124-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_124-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_101-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_104-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_109-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_114-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_117-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_120-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_125-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_175-94_79-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_175-94_79-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_176-94_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_176-94_88-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_178-94_91-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_178-94_91-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_100-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_100-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_103-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_103-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_107-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_107-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_113-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_113-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_97-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_97-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_110-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_110-xen-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_115-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_115-xen-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_118-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_118-xen-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_121-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_121-xen-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_124-default-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_124-xen-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_175-94_79-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_175-94_79-default-debuginfo-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_176-94_88-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_176-94_88-default-debuginfo-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_178-94_91-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_178-94_91-default-debuginfo-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_100-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_100-default-debuginfo-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_103-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_103-default-debuginfo-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_107-default-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_107-default-debuginfo-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_113-default-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_113-default-debuginfo-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_97-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_97-default-debuginfo-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_101-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_104-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_109-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_114-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_117-default-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_120-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_125-default-3-2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
