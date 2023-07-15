#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0408-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146401);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2020-29569",
    "CVE-2020-29660",
    "CVE-2020-29661",
    "CVE-2020-36158"
  );

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:0408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for the Linux Kernel 4.4.180-94_121 fixes several issues.

The following security issues were fixed :

CVE-2020-36158: Fixed a potential remote code execution in the Marvell
mwifiex driver (bsc#1180562).

CVE-2020-0465: Fixed multiple missing bounds checks in
hid-multitouch.c that could have led to local privilege escalation
(bnc#1180030).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180032.

CVE-2020-29569: Fixed a use after free due to a logic error
(bsc#1180008).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem
that may have allowed a read-after-free attack against TIOCGSID
(bsc#1179877).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that
allowed a use-after-free attack against TIOCSPGRP (bsc#1179877).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0465/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0466/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29569/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29660/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29661/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36158/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210408-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de7ce351");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2021-404=1
SUSE-SLE-SAP-12-SP3-2021-405=1 SUSE-SLE-SAP-12-SP3-2021-406=1
SUSE-SLE-SAP-12-SP3-2021-407=1 SUSE-SLE-SAP-12-SP3-2021-408=1
SUSE-SLE-SAP-12-SP3-2021-409=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2021-410=1
SUSE-SLE-SAP-12-SP2-2021-411=1 SUSE-SLE-SAP-12-SP2-2021-412=1
SUSE-SLE-SAP-12-SP2-2021-413=1 SUSE-SLE-SAP-12-SP2-2021-414=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2021-404=1
SUSE-SLE-SERVER-12-SP3-2021-405=1 SUSE-SLE-SERVER-12-SP3-2021-406=1
SUSE-SLE-SERVER-12-SP3-2021-407=1 SUSE-SLE-SERVER-12-SP3-2021-408=1
SUSE-SLE-SERVER-12-SP3-2021-409=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2021-410=1
SUSE-SLE-SERVER-12-SP2-2021-411=1 SUSE-SLE-SERVER-12-SP2-2021-412=1
SUSE-SLE-SERVER-12-SP2-2021-413=1 SUSE-SLE-SERVER-12-SP2-2021-414=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36158");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_129-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_135-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_138-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_141-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_146-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_121-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_121-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_124-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_124-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_127-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_127-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_130-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_130-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_135-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_135-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-7-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-debuginfo-7-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_121-default-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_121-default-debuginfo-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_124-default-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_124-default-debuginfo-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_127-default-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_127-default-debuginfo-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_130-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_130-default-debuginfo-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_135-default-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_135-default-debuginfo-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_129-default-8-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_135-default-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_138-default-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_141-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_146-default-3-2.1")) flag++;


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
