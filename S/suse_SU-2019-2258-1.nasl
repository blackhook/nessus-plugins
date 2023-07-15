#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2258-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128466);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/10 13:51:52");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Recommended update for NetworkManager (SUSE-SU-2019:2258-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for NetworkManager fixes the following issues :

Security issue fixed :

Fixed that passwords are not echoed on terminal when asking for them
(bsc#990204).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990204"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192258-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b69dced"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-2258=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-2258=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2258=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2258=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-glib-vpn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-glib-vpn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-glib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-glib4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-util2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm-util2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnm0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-NM");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-NMClient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-NetworkManager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"NetworkManager-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"NetworkManager-debugsource-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-glib-vpn1-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-glib-vpn1-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-glib4-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-glib4-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-util2-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm-util2-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnm0-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-NMClient-1_0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"typelib-1_0-NetworkManager-1_0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"NetworkManager-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"NetworkManager-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"NetworkManager-debugsource-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-glib-vpn1-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-glib-vpn1-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-glib4-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-glib4-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-util2-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm-util2-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnm0-debuginfo-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-NM-1_0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-NMClient-1_0-1.0.12-13.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"typelib-1_0-NetworkManager-1_0-1.0.12-13.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for NetworkManager");
}
