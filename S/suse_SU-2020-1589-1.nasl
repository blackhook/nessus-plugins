#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1589-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(137609);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/22");

  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ucode-intel (SUSE-SU-2020:1589-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ucode-intel fixes the following issues :

Updated Intel CPU Microcode to 20200602 (prerelease) (bsc#1172466)

This update contains security mitigations for :

CVE-2020-0543: Fixed a side channel attack against special registers
which could have resulted in leaking of read values to cores other
than the one which called it. This attack is known as Special Register
Buffer Data Sampling (SRBDS) or 'CrossTalk' (bsc#1154824).

CVE-2020-0548,CVE-2020-0549: Additional ucode updates were supplied to
mitigate the Vector Register and L1D Eviction Sampling aka
'CacheOutAttack' attacks. (bsc#1156353)

Microcode Table :

Processor Identifier Version Products Model Stepping F-MO-S/PI
Old->New

---- new platforms ----------------------------------------

---- updated platforms ------------------------------------
HSW C0 6-3c-3/32 00000027->00000028 Core Gen4 BDW-U/Y E0/F0
6-3d-4/c0 0000002e->0000002f Core Gen5 HSW-U C0/D0 6-45-1/72
00000025->00000026 Core Gen4 HSW-H C0 6-46-1/32
0000001b->0000001c Core Gen4 BDW-H/E3 E0/G0 6-47-1/22
00000021->00000022 Core Gen5 SKL-U/Y D0 6-4e-3/c0
000000d6->000000dc Core Gen6 Mobile SKL-U23e K1 6-4e-3/c0
000000d6->000000dc Core Gen6 Mobile SKX-SP B1 6-55-3/97
01000151->01000157 Xeon Scalable SKX-SP H0/M0/U0 6-55-4/b7
02000065->02006906 Xeon Scalable SKX-D M1 6-55-4/b7
02000065->02006906 Xeon D-21xx CLX-SP B0 6-55-6/bf
0400002c->04002f01 Xeon Scalable Gen2 CLX-SP B1 6-55-7/bf
0500002c->04002f01 Xeon Scalable Gen2 SKL-H/S R0/N0
6-5e-3/36 000000d6->000000dc Core Gen6; Xeon E3 v5 AML-Y22
H0 6-8e-9/10 000000ca->000000d6 Core Gen8 Mobile KBL-U/Y H0
6-8e-9/c0 000000ca->000000d6 Core Gen7 Mobile CFL-U43e D0
6-8e-a/c0 000000ca->000000d6 Core Gen8 Mobile WHL-U W0
6-8e-b/d0 000000ca->000000d6 Core Gen8 Mobile AML-Y42 V0
6-8e-c/94 000000ca->000000d6 Core Gen10 Mobile CML-Y42 V0
6-8e-c/94 000000ca->000000d6 Core Gen10 Mobile WHL-U V0
6-8e-c/94 000000ca->000000d6 Core Gen8 Mobile KBL-G/H/S/E3
B0 6-9e-9/2a 000000ca->000000d6 Core Gen7; Xeon E3 v6
CFL-H/S/E3 U0 6-9e-a/22 000000ca->000000d6 Core Gen8
Desktop, Mobile, Xeon E CFL-S B0 6-9e-b/02
000000ca->000000d6 Core Gen8 CFL-H/S P0 6-9e-c/22
000000ca->000000d6 Core Gen9 CFL-H R0 6-9e-d/22
000000ca->000000d6 Core Gen9 Mobile

Also contains the Intel CPU Microcode update to 20200520 :

Processor Identifier Version Products Model Stepping F-MO-S/PI
Old->New

---- new platforms ----------------------------------------

---- updated platforms ------------------------------------
SNB-E/EN/EP C1/M0 6-2d-6/6d 0000061f->00000621 Xeon E3/E5,
Core X SNB-E/EN/EP C2/M1 6-2d-7/6d 00000718->0000071a Xeon
E3/E5, Core X

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-0543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-0548/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-0549/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201589-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4083bf71"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-1589=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ucode-intel-20200602-3.25.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ucode-intel-20200602-3.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ucode-intel");
}
