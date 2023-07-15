#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1482-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110284);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2018:1482-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes. This update main focus is a regression fix in
SystemV IPC handling. (bsc#1093600)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1093710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919382"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181482-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7b0ed2a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-20180526-13635=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-20180526-13635=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-20180526-13635=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-20180526-13635=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-108.52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-108.52.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
