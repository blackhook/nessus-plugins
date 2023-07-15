#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0414-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(106747);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2016-10244", "CVE-2017-7864", "CVE-2017-8105", "CVE-2017-8287");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : freetype2 (SUSE-SU-2018:0414-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for freetype2 fixes the following security issues :

  - CVE-2016-10244: Make sure that the parse_charstrings
    function in type1/t1load.c does ensure that a font
    contains a glyph name to prevent a DoS through a
    heap-based buffer over-read or possibly have unspecified
    other impact via a crafted file (bsc#1028103)

  - CVE-2017-8105: Fix an out-of-bounds write caused by a
    heap-based buffer overflow related to the
    t1_decoder_parse_charstrings function in
    psaux/t1decode.ca (bsc#1035807)

  - CVE-2017-8287: an out-of-bounds write caused by a
    heap-based buffer overflow related to the
    t1_builder_close_contour function in psaux/psobjs.c
    (bsc#1036457)

  - Fix several integer overflow issues in
    truetype/ttinterp.c (bsc#1079600)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1028103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10244/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7864/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8287/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180414-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5427ba60"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-286=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-286=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2018-286=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-286=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-286=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-286=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2018-286=1

SUSE CaaS Platform ALL:zypper in -t patch SUSE-CAASP-ALL-2018-286=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ft2demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"freetype2-debugsource-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"ft2demos-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreetype6-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreetype6-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreetype6-debuginfo-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libfreetype6-debuginfo-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"freetype2-debugsource-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"ft2demos-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreetype6-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreetype6-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreetype6-debuginfo-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libfreetype6-debuginfo-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"freetype2-debugsource-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"ft2demos-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreetype6-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreetype6-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreetype6-debuginfo-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"freetype2-debugsource-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ft2demos-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreetype6-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreetype6-32bit-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreetype6-debuginfo-2.6.3-7.15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.6.3-7.15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2");
}
