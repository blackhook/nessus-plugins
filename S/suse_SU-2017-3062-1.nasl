#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3062-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104778);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"SUSE SLED12 Security Update : gimp (SUSE-SU-2017:3062-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gimp fixes the following issues :

  - Don't build gimp with webkit1 support, as it is no
    longer maintained and has plenty of security bugs. This
    disables the GIMP's built-in help browser; it will use
    an external browser when configured this way. This works
    around a number of security vulnerabilities in Webkit1.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050469"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173062-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82fe8da8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2017-1887=1

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1887=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2017-1887=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1887=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2017-1887=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1887=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gimp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gimp-plugins-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgimp-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgimp-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgimpui-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgimpui-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
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
if (! preg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gimp-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gimp-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gimp-debugsource-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gimp-plugins-python-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"gimp-plugins-python-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgimp-2_0-0-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgimpui-2_0-0-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gimp-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gimp-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gimp-debugsource-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gimp-plugins-python-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"gimp-plugins-python-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgimp-2_0-0-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgimp-2_0-0-debuginfo-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgimpui-2_0-0-2.8.18-9.3.26")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libgimpui-2_0-0-debuginfo-2.8.18-9.3.26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp");
}
