#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0234-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(133259);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2007-2052",
    "CVE-2008-1721",
    "CVE-2008-2315",
    "CVE-2008-2316",
    "CVE-2008-3142",
    "CVE-2008-3143",
    "CVE-2008-3144",
    "CVE-2011-1521",
    "CVE-2011-3389",
    "CVE-2011-4944",
    "CVE-2012-0845",
    "CVE-2012-1150",
    "CVE-2013-1752",
    "CVE-2013-1753",
    "CVE-2013-4238",
    "CVE-2014-1912",
    "CVE-2014-4650",
    "CVE-2014-7185",
    "CVE-2016-0772",
    "CVE-2016-1000110",
    "CVE-2016-5636",
    "CVE-2016-5699",
    "CVE-2017-1000158",
    "CVE-2017-18207",
    "CVE-2018-1000030",
    "CVE-2018-1000802",
    "CVE-2018-1060",
    "CVE-2018-1061",
    "CVE-2018-14647",
    "CVE-2018-20852",
    "CVE-2019-10160",
    "CVE-2019-16056",
    "CVE-2019-16935",
    "CVE-2019-5010",
    "CVE-2019-9636",
    "CVE-2019-9947",
    "CVE-2019-9948"
  );
  script_bugtraq_id(
    28715,
    30491,
    47024,
    49388,
    49778,
    51239,
    52732,
    61738,
    63804,
    65379,
    66958,
    68147,
    70089
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : python (SUSE-SU-2020:0234-1) (BEAST) (httpoxy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for python fixes the following issues :

Updated to version 2.7.17 to unify packages among openSUSE:Factory and
SLE versions (bsc#1159035).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1027282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1041090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1042670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1068664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1073269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1073748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1078326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1078485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1079300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1081750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1083507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1086001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1111793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1113755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1122191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1129346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1130847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1138459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1153830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=214983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=298378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=346490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=367853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=379534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=380942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=399190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=406051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=425138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=426563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=430761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=432677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=436966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=437293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=441088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=462375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=525295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=534721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=551715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=572673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=577032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=581765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=603255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=617751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=637176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=638233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=658604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=673071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=682554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=697251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=707667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=718009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=747125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=747794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=751718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=754447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=766778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=794139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=804978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=827982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=831442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=834601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=836739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=856835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=856836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=857470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=863741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=885882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=898572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=901715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=935856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=945401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=964182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=984751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=985177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=985348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=989523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2007-2052/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-1721/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-2315/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-2316/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-3142/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-3143/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2008-3144/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-1521/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-3389/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2011-4944/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-0845/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2012-1150/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2013-1752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2013-1753/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2013-4238/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-1912/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-4650/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-7185/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-0772/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1000110/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5636/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5699/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-1000158/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18207/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000030/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000802/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1060/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1061/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20852/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-10160/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16056/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-16935/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5010/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9636/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9947/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9948/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200234-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7e022df");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Python2 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP1-2020-234=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-234=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-OBS-15-2020-234=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-234=1

SUSE Linux Enterprise Module for Desktop Applications 15 :

zypper in -t patch SUSE-SLE-Module-Desktop-Applications-15-2020-234=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-234=1

SUSE Linux Enterprise Module for Basesystem 15 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-2020-234=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python-32bit-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python-32bit-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python-base-32bit-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"python-base-32bit-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpython2_7-1_0-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpython2_7-1_0-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-base-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-base-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-base-debugsource-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-curses-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-curses-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-debugsource-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-demo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-devel-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-gdbm-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-gdbm-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-idle-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-tk-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-tk-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-xml-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-xml-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpython2_7-1_0-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpython2_7-1_0-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-base-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-base-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-base-debugsource-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-curses-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-curses-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-debugsource-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-demo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-devel-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-gdbm-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-gdbm-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-idle-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tk-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tk-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-xml-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-xml-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python-32bit-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python-32bit-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python-base-32bit-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"python-base-32bit-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpython2_7-1_0-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpython2_7-1_0-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-base-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-base-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-base-debugsource-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-curses-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-curses-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-debugsource-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-demo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-devel-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-gdbm-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-gdbm-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-idle-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-tk-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-tk-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-xml-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-xml-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpython2_7-1_0-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpython2_7-1_0-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-base-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-base-debuginfo-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-base-debugsource-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-curses-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-curses-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-debugsource-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-demo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-devel-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-gdbm-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-gdbm-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-idle-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tk-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tk-debuginfo-2.7.17-7.32.2")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-xml-2.7.17-7.32.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-xml-debuginfo-2.7.17-7.32.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
