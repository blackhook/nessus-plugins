#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0712-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(123068);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/10 13:51:50");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ucode-intel (SUSE-SU-2019:0712-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ucode-intel fixes the following issues :

Updated to the 20190312 bundle release (bsc#1129231)

New Platforms :

AML-Y22 H0 6-8e-9/10 0000009e Core Gen8 Mobile

WHL-U W0 6-8e-b/d0 000000a4 Core Gen8 Mobile

WHL-U V0 6-8e-d/94 000000b2 Core Gen8 Mobile

CFL-S P0 6-9e-c/22 000000a2 Core Gen9 Desktop

CFL-H R0 6-9e-d/22 000000b0 Core Gen9 Mobile

Updated Platforms: HSX-E/EP Cx/M1 6-3f-2/6f 0000003d->00000041 Core
Gen4 X series; Xeon E5 v3

HSX-EX E0 6-3f-4/80 00000012->00000013 Xeon E7 v3

SKX-SP H0/M0/U0 6-55-4/b7 0200004d->0000005a Xeon Scalable

SKX-D M1 6-55-4/b7 0200004d->0000005a Xeon D-21xx

BDX-DE V1 6-56-2/10 00000017->00000019 Xeon D-1520/40

BDX-DE V2/3 6-56-3/10 07000013->07000016 Xeon
D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19

BDX-DE Y0 6-56-4/10 0f000012->0f000014 Xeon D-1557/59/67/71/77/81/87

BDX-NS A0 6-56-5/10 0e00000a->0e00000c Xeon D-1513N/23/33/43/53

APL D0 6-5c-9/03 00000032->00000036 Pentium N/J4xxx, Celeron N/J3xxx,
Atom x5/7-E39xx

APL E0 6-5c-a/03 0000000c->00000010 Atom x5/7-E39xx

GLK B0 6-7a-1/01 00000028->0000002c Pentium Silver N/J5xxx, Celeron
N/J4xxx

KBL-U/Y H0 6-8e-9/c0 0000008e->0000009a Core Gen7 Mobile

CFL-U43e D0 6-8e-a/c0 00000096->0000009e Core Gen8 Mobile

KBL-H/S/E3 B0 6-9e-9/2a 0000008e->0000009a Core Gen7; Xeon E3 v6

CFL-H/S/E3 U0 6-9e-a/22 00000096->000000aa Core Gen8 Desktop, Mobile,
Xeon E

CFL-S B0 6-9e-b/02 0000008e->000000aa Core Gen8

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1129231"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190712-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9179d168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-712=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/25");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"ucode-intel-20190312-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"ucode-intel-20190312-3.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel");
}
