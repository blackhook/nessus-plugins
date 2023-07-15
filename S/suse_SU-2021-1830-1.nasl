#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1830-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150190);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2018-25009", "CVE-2018-25010", "CVE-2018-25011", "CVE-2018-25012", "CVE-2018-25013", "CVE-2020-36329", "CVE-2020-36330", "CVE-2020-36331", "CVE-2020-36332");

  script_name(english:"SUSE SLES12 Security Update : libwebp (SUSE-SU-2021:1830-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libwebp fixes the following issues :

CVE-2018-25010: Fixed heap-based buffer overflow in ApplyFilter()
(bsc#1185685).

CVE-2020-36330: Fixed heap-based buffer overflow in
ChunkVerifyAndAssign() (bsc#1185691).

CVE-2020-36332: Fixed extreme memory allocation when reading a file
(bsc#1185674).

CVE-2020-36329: Fixed use-after-free in EmitFancyRGB() (bsc#1185652).

CVE-2018-25012: Fixed heap-based buffer overflow in GetLE24()
(bsc#1185690).

CVE-2018-25013: Fixed heap-based buffer overflow in ShiftBytes()
(bsc#1185654).

CVE-2020-36331: Fixed heap-based buffer overflow in ChunkAssignData()
(bsc#1185686).

CVE-2018-25009: Fixed heap-based buffer overflow in GetLE16()
(bsc#1185673).

CVE-2018-25011: Fixed fail on multiple image chunks (bsc#1186247).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1186247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-25009/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-25010/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-25011/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-25012/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-25013/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36329/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36330/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36331/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-36332/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211830-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3e1df43"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-1830=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2021-1830=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-1830=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2021-1830=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2021-1830=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-1830=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-1830=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2021-1830=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-1830=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-1830=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2021-1830=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2021-1830=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2021-1830=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2021-1830=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebp5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebpdemux1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebpdemux1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebp-debugsource-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebp5-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebp5-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebp5-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebp5-debuginfo-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebpdemux1-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwebpdemux1-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebp-debugsource-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebp5-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebp5-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebp5-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebp5-debuginfo-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebpdemux1-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwebpdemux1-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebp-debugsource-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebp5-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebp5-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebp5-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebp5-debuginfo-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebpdemux1-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libwebpdemux1-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebp-debugsource-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebp5-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebp5-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebp5-debuginfo-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebp5-debuginfo-32bit-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebpdemux1-0.4.3-4.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libwebpdemux1-debuginfo-0.4.3-4.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebp");
}
