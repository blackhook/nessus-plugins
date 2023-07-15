#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3433-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143710);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-25645");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2020:3433-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for the Linux Kernel 4.4.180-94_113 fixes one issue.

The following security issue was fixed :

CVE-2020-25645: Fixed an an issue in IPsec that caused traffic between
two Geneve endpoints to be unencrypted (bnc#1177513).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1177513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-25645/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203433-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecffcf5a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-3426=1
SUSE-SLE-SAP-12-SP3-2020-3427=1 SUSE-SLE-SAP-12-SP3-2020-3429=1
SUSE-SLE-SAP-12-SP3-2020-3430=1 SUSE-SLE-SAP-12-SP3-2020-3432=1
SUSE-SLE-SAP-12-SP3-2020-3433=1 SUSE-SLE-SAP-12-SP3-2020-3445=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-3428=1
SUSE-SLE-SAP-12-SP2-2020-3431=1 SUSE-SLE-SAP-12-SP2-2020-3434=1
SUSE-SLE-SAP-12-SP2-2020-3436=1 SUSE-SLE-SAP-12-SP2-2020-3443=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-3426=1
SUSE-SLE-SERVER-12-SP3-2020-3427=1 SUSE-SLE-SERVER-12-SP3-2020-3429=1
SUSE-SLE-SERVER-12-SP3-2020-3430=1 SUSE-SLE-SERVER-12-SP3-2020-3432=1
SUSE-SLE-SERVER-12-SP3-2020-3433=1 SUSE-SLE-SERVER-12-SP3-2020-3445=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-3428=1
SUSE-SLE-SERVER-12-SP2-2020-3431=1 SUSE-SLE-SERVER-12-SP2-2020-3434=1
SUSE-SLE-SERVER-12-SP2-2020-3436=1 SUSE-SLE-SERVER-12-SP2-2020-3443=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_125-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_129-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_135-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_138-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_141-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_107-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_107-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_113-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_113-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_116-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_121-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_121-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_124-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_124-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_127-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_127-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_130-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_130-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_107-default-9-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_107-default-debuginfo-9-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_113-default-8-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_113-default-debuginfo-8-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-5-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_116-default-debuginfo-5-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_121-default-4-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_121-default-debuginfo-4-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_124-default-4-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_124-default-debuginfo-4-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_127-default-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_127-default-debuginfo-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_130-default-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_130-default-debuginfo-3-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_125-default-9-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_129-default-6-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_135-default-4-2.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_138-default-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_141-default-3-2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
