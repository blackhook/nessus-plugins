#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3087-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131549);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libxml2 (SUSE-SU-2019:3087-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libxml2 doesn't fix any additional security issues,
but correct its rpm changelog to reflect all CVEs that have been fixed
over the past.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123919"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193087-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?324294c7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Python2 15-SP1:zypper in -t patch
SUSE-SLE-Module-Python2-15-SP1-2019-3087=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-3087=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-3087=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-3087=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-3087=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libxml2-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-2-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-2-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-devel-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-tools-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libxml2-tools-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-libxml2-python-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-2-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-2-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-devel-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-tools-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libxml2-tools-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-libxml2-python-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python2-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-2-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-2-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-devel-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-tools-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libxml2-tools-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-libxml2-python-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python2-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-2-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-2-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-devel-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-tools-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libxml2-tools-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-libxml2-python-debugsource-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python2-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-libxml2-python-2.9.7-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-libxml2-python-debuginfo-2.9.7-3.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
