#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2075-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102256);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ncurses (SUSE-SU-2017:2075-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ncurses fixes the following issues: Security issues
fixed :

  - CVE-2017-11112: Illegal address access in append_acs.
    (bsc#1047964)

  - CVE-2017-11113: Dereferencing NULL pointer in
    _nc_parse_entry. (bsc#1047965)

  - CVE-2017-10684, CVE-2017-10685: Add modified upstream
    fix from ncurses 6.0 to avoid broken termcap format
    (bsc#1046853, bsc#1046858, bsc#1049344)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10684/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10685/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11113/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172075-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c756581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1279=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1279=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1279=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2017-1279=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1279=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1279=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1279=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-1279=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libncurses6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ncurses-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:terminfo-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses5-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses5-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses6-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses6-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-debugsource-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-devel-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-devel-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-utils-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-utils-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tack-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tack-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"terminfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"terminfo-base-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses5-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses5-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses6-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libncurses6-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-devel-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ncurses-devel-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses5-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses5-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses6-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses6-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-debugsource-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-devel-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-devel-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-utils-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-utils-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"tack-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"tack-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"terminfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"terminfo-base-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses5-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses5-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses6-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libncurses6-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-devel-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ncurses-devel-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses5-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses5-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses5-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses5-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses6-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses6-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses6-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libncurses6-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ncurses-debugsource-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ncurses-devel-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ncurses-devel-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ncurses-utils-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ncurses-utils-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"tack-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"tack-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"terminfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"terminfo-base-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses5-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses5-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses5-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses5-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses6-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses6-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses6-debuginfo-32bit-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libncurses6-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ncurses-debugsource-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ncurses-devel-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ncurses-devel-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ncurses-utils-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ncurses-utils-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"tack-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"tack-debuginfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"terminfo-5.9-50.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"terminfo-base-5.9-50.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncurses");
}
