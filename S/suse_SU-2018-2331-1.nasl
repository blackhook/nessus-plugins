#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2331-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(111781);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639", "CVE-2018-3640", "CVE-2018-3646");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Security update to ucode-intel (SUSE-SU-2018:2331-1) (Foreshadow) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"ucode-intel was updated to the 20180807 release. For the listed CPU
chipsets this fixes CVE-2018-3640 (Spectre v3a) and is part of the
mitigations for CVE-2018-3639 (Spectre v4) and CVE-2018-3646 (L1
Terminal fault). (bsc#1104134 bsc#1087082 bsc#1087083 bsc#1089343)
Processor Identifier Version Products Model Stepping F-MO-S/PI
Old->New

---- new platforms ---------------------------------------- WSM-EP/WS
U1 6-2c-2/03 0000001f Xeon E/L/X56xx, W36xx NHM-EX D0 6-2e-6/04
0000000d Xeon E/L/X65xx/75xx BXT C0 6-5c-2/01 00000014 Atom T5500/5700
APL E0 6-5c-a/03 0000000c Atom x5-E39xx DVN B0 6-5f-1/01 00000024 Atom
C3xxx

---- updated platforms ------------------------------------
NHM-EP/WS D0 6-1a-5/03 00000019->0000001d Xeon E/L/X/W55xx
NHM B1 6-1e-5/13 00000007->0000000a Core i7-8xx, i5-7xx;
Xeon L3426, X24xx WSM B1 6-25-2/12 0000000e->00000011 Core
i7-6xx, i5-6xx/4xxM, i3-5xx/3xxM, Pentium G69xx, Celeon
P45xx; Xeon L3406 WSM K0 6-25-5/92 00000004->00000007 Core
i7-6xx, i5-6xx/5xx/4xx, i3-5xx/3xx, Pentium
G69xx/P6xxx/U5xxx, Celeron P4xxx/U3xxx SNB D2 6-2a-7/12
0000002d->0000002e Core Gen2; Xeon E3 WSM-EX A2 6-2f-2/05
00000037->0000003b Xeon E7 IVB E2 6-3a-9/12
0000001f->00000020 Core Gen3 Mobile HSW-H/S/E3 Cx/Dx
6-3c-3/32 00000024->00000025 Core Gen4 Desktop; Xeon E3 v3
BDW-U/Y E/F 6-3d-4/c0 0000002a->0000002b Core Gen5 Mobile
HSW-ULT Cx/Dx 6-45-1/72 00000023->00000024 Core Gen4 Mobile
and derived Pentium/Celeron HSW-H Cx 6-46-1/32
00000019->0000001a Core Extreme i7-5xxxX BDW-H/E3 E/G
6-47-1/22 0000001d->0000001e Core i5-5xxxR/C, i7-5xxxHQ/EQ;
Xeon E3 v4 SKL-U/Y D0 6-4e-3/c0 000000c2->000000c6 Core Gen6
Mobile BDX-DE V1 6-56-2/10 00000015->00000017 Xeon D-1520/40
BDX-DE V2/3 6-56-3/10 07000012->07000013 Xeon
D-1518/19/21/27/28/31/33/37/41/48, Pentium D1507/08/09/17/19
BDX-DE Y0 6-56-4/10 0f000011->0f000012 Xeon
D-1557/59/67/71/77/81/87 APL D0 6-5c-9/03 0000002c->00000032
Pentium N/J4xxx, Celeron N/J3xxx, Atom x5/7-E39xx SKL-H/S/E3
R0 6-5e-3/36 000000c2->000000c6 Core Gen6; Xeon E3 v5

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3646/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182331-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?071af209"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1573=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1573=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1573=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1573=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1573=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1573=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1573=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1573=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1573=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"ucode-intel-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"ucode-intel-debuginfo-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"ucode-intel-debugsource-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"ucode-intel-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"ucode-intel-debuginfo-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"ucode-intel-debugsource-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"ucode-intel-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"ucode-intel-debuginfo-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"ucode-intel-debugsource-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ucode-intel-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ucode-intel-debuginfo-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ucode-intel-debugsource-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ucode-intel-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ucode-intel-debuginfo-20180807-13.29.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ucode-intel-debugsource-20180807-13.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Security update to ucode-intel");
}
