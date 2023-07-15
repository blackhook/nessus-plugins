#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1690-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110544);
  script_version("1.6");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2018:1690-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk to version 8u171 fixes the
following issues: These security issues were fixed :

  - S8180881: Better packaging of deserialization

  - S8182362: Update CipherOutputStream Usage

  - S8183032: Upgrade to LittleCMS 2.9

  - S8189123: More consistent classloading

  - S8189969, CVE-2018-2790, bsc#1090023: Manifest better
    manifest entries

  - S8189977, CVE-2018-2795, bsc#1090025: Improve permission
    portability

  - S8189981, CVE-2018-2796, bsc#1090026: Improve queuing
    portability

  - S8189985, CVE-2018-2797, bsc#1090027: Improve tabular
    data portability

  - S8189989, CVE-2018-2798, bsc#1090028: Improve container
    portability

  - S8189993, CVE-2018-2799, bsc#1090029: Improve document
    portability

  - S8189997, CVE-2018-2794, bsc#1090024: Enhance keystore
    mechanisms

  - S8190478: Improved interface method selection

  - S8190877: Better handling of abstract classes

  - S8191696: Better mouse positioning

  - S8192025, CVE-2018-2814, bsc#1090032: Less referential
    references

  - S8192030: Better MTSchema support

  - S8192757, CVE-2018-2815, bsc#1090033: Improve stub
    classes implementation

  - S8193409: Improve AES supporting classes

  - S8193414: Improvements in MethodType lookups

  - S8193833, CVE-2018-2800, bsc#1090030: Better RMI
    connection support For other changes please consult the
    changelog.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2790/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2794/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2795/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2796/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2797/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2798/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2799/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2800/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2814/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2815/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181690-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3531cca1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1134=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1134=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1134=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1134=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1134=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1134=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1134=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1134=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.171-27.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.171-27.19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk");
}
