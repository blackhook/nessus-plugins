#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1524-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(137580);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-18348", "CVE-2019-9674", "CVE-2020-8492");

  script_name(english:"SUSE SLES12 Security Update : python (SUSE-SU-2020:1524-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python to version 2.7.17 fixes the following issues :

Syncing with lots of upstream bug fixes and security fixes.

Bug fixes :

CVE-2019-9674: Improved the documentation to reflect the dangers of
zip-bombs (bsc#1162825).

CVE-2019-18348: Fixed a CRLF injection via the host part of the url
passed to urlopen(). Now an InvalidURL exception is raised
(bsc#1155094).

CVE-2020-8492: Fixed a regular expression in urllib that was prone to
denial of service via HTTP (bsc#1162367).

Fixed mismatches between libpython and python-base versions
(bsc#1162224).

Fixed segfault in libpython2.7.so.1 (bsc#1073748).

Unified packages among openSUSE:Factory and SLE versions
(bsc#1159035).

Added idle.desktop and idle.appdata.xml to provide IDLE in menus
(bsc#1153830).

Excluded tsl_check files from python-base to prevent file conflict
with python-strict-tls-checks package (bsc#945401).

Changed the name of idle3 icons to idle3.png to avoid collision with
Python 2 version (bsc#1165894).

Additionally a new 'shared-python-startup' package is provided
containing startup files.

python-rpm-macros was updated to fix :

Do not write .pyc files for tests (bsc#1171561)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1041090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1084650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1086001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1165894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=945401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-18348/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9674/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8492/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201524-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0962fb1f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1524=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1524=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-1524=1

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2020-1524=1

SUSE Linux Enterprise Workstation Extension 12-SP4 :

zypper in -t patch SUSE-SLE-WE-12-SP4-2020-1524=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-1524=1

SUSE Linux Enterprise Software Development Kit 12-SP4 :

zypper in -t patch SUSE-SLE-SDK-12-SP4-2020-1524=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1524=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-1524=1

SUSE Linux Enterprise Server for SAP 12-SP1 :

zypper in -t patch SUSE-SLE-SAP-12-SP1-2020-1524=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1524=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1524=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1524=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1524=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-1524=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-1524=1

SUSE Linux Enterprise Server 12-SP1-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2020-1524=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1524=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1524=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18348");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-demo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-devel-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-idle-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-curses-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-curses-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-demo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-devel-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-gdbm-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-gdbm-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-idle-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-tk-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-tk-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-xml-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-xml-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-curses-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-curses-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-demo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-devel-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-gdbm-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-gdbm-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-idle-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-tk-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-tk-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-xml-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-xml-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-curses-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-curses-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-demo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-devel-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-gdbm-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-gdbm-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-idle-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-tk-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-tk-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-xml-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-xml-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython2_7-1_0-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython2_7-1_0-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython2_7-1_0-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-base-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-base-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-base-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-base-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-base-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-curses-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-curses-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-debuginfo-32bit-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-debugsource-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-demo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-devel-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-gdbm-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-gdbm-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-idle-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-tk-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-tk-debuginfo-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-xml-2.7.17-28.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-xml-debuginfo-2.7.17-28.42.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
