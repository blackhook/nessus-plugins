#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0114-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(133036);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-4944",
    "CVE-2012-0845",
    "CVE-2012-1150",
    "CVE-2013-1752",
    "CVE-2013-4238",
    "CVE-2014-2667",
    "CVE-2014-4650",
    "CVE-2016-0772",
    "CVE-2016-1000110",
    "CVE-2016-5636",
    "CVE-2016-5699",
    "CVE-2017-18207",
    "CVE-2018-1000802",
    "CVE-2018-1060",
    "CVE-2018-1061",
    "CVE-2018-14647",
    "CVE-2018-20406",
    "CVE-2018-20852",
    "CVE-2019-10160",
    "CVE-2019-15903",
    "CVE-2019-16056",
    "CVE-2019-16935",
    "CVE-2019-5010",
    "CVE-2019-9636",
    "CVE-2019-9947"
  );
  script_bugtraq_id(
    49388,
    49778,
    51239,
    52732,
    61738,
    63804,
    66521,
    68147
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : python3 (SUSE-SU-2020:0114-1) (BEAST) (httpoxy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for python3 to version 3.6.10 fixes the following issues :

CVE-2017-18207: Fixed a denial of service in
Wave_read._read_fmt_chunk() (bsc#1083507).

CVE-2019-16056: Fixed an issue where email parsing could fail for
multiple @ (bsc#1149955).

CVE-2019-15903: Fixed a heap-based buffer over-read in libexpat
(bsc#1149429).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1027282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1029377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1029902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1040164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1042670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1070853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1081750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1083507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1086001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1094814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1107030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1122191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1129346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1133452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1138459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1151490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=637176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=658604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=673071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=709442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=743787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=747125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=751718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=754447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=754677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=787526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=809831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=831629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=834601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=871152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=885662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=885882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=917607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=942751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=951166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=983582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=984751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=985177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=985348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=989523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-3389/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-4944/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-0845/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-1150/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2013-1752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2013-4238/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-2667/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-4650/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0772/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1000110/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5636/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5699/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18207/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000802/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1060/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1061/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20406/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20852/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10160/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15903/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16056/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16935/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5010/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9636/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9947/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200114-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a736fc2");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-114=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-OBS-15-2020-114=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-114=1

SUSE Linux Enterprise Module for Development Tools 15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-2020-114=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-114=1

SUSE Linux Enterprise Module for Basesystem 15 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-2020-114=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_6m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_6m1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_6m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python3-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python3-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python3-base-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python3-base-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpython3_6m1_0-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpython3_6m1_0-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-base-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-base-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-base-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-curses-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-curses-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-dbm-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-dbm-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-devel-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-devel-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-idle-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-testsuite-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-testsuite-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-tk-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-tk-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-tools-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"python3-base-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpython3_6m1_0-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpython3_6m1_0-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-base-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-base-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-base-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-curses-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-curses-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-dbm-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-dbm-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-devel-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-devel-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-idle-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-testsuite-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-testsuite-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tk-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tk-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tools-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python3-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python3-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python3-base-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python3-base-32bit-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpython3_6m1_0-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpython3_6m1_0-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-base-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-base-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-base-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-curses-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-curses-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-dbm-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-dbm-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-devel-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-devel-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-idle-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-testsuite-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-testsuite-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-tk-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-tk-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-tools-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"python3-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"python3-base-32bit-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpython3_6m1_0-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpython3_6m1_0-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-base-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-base-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-base-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-curses-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-curses-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-dbm-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-dbm-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-debugsource-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-devel-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-devel-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-idle-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-testsuite-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-testsuite-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tk-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tk-debuginfo-3.6.10-3.42.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tools-3.6.10-3.42.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3");
}
