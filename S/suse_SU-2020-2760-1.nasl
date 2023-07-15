#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2760-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143793);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-17507");

  script_name(english:"SUSE SLES12 Security Update : libqt5-qtbase (SUSE-SU-2020:2760-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libqt5-qtbase fixes the following issues :

CVE-2020-17507: Fixed a buffer overflow in XBM parser (bsc#1176315)

Made handling of XDG_RUNTIME_DIR more secure (bsc#1172515)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1176315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-17507/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202760-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a71fbc47"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-2760=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-2760=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-2760=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-2760=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Concurrent5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Concurrent5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Core5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Core5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5DBus5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5DBus5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Gui5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Gui5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Network5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Network5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5OpenGL5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5OpenGL5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5PrintSupport5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5PrintSupport5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-mysql-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-mysql-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-postgresql-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-postgresql-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-sqlite-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-sqlite-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-unixODBC-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Sql5-unixODBC-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Test5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Test5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Widgets5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Widgets5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Xml5-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libQt5Xml5-debuginfo-5.6.1-17.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libqt5-qtbase-debugsource-5.6.1-17.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt5-qtbase");
}
