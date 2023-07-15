#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:3085-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(131547);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libxml2 (SUSE-SU-2019:3085-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libxml2 doesn't fix any additional security issues,
but correct the rpm changelog to reflect all CVEs that have been fixed
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
  # https://www.suse.com/support/update/announcement/2019/suse-su-20193085-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?642b2975"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-3085=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-3085=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-3085=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-3085=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-3085=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-2-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-2-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-2-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-2-debuginfo-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-debugsource-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-tools-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libxml2-tools-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-libxml2-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-libxml2-debuginfo-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-libxml2-debugsource-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-2-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-2-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-2-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-2-debuginfo-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-debugsource-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-tools-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libxml2-tools-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-libxml2-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-libxml2-debuginfo-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-libxml2-debugsource-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-2-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-2-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-debugsource-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-tools-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libxml2-tools-debuginfo-2.9.4-46.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-libxml2-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-libxml2-debuginfo-2.9.4-46.23.3")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-libxml2-debugsource-2.9.4-46.23.3")) flag++;


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
