#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2600-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(129746);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/19");

  script_cve_id("CVE-2017-18379", "CVE-2019-14835");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2019:2600-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the Linux Kernel 4.4.180-94_100 fixes several issues.

The following security issues were fixed :

CVE-2019-14835: A buffer overflow flaw was found in the way vhost
functionality, that translates virtqueue buffers to IOVs, logged the
buffer descriptors during migration. A privileged guest user able to
pass descriptors with invalid length to the host when migration is
underway, could use this flaw to increase their privileges on the host
(bsc#1151021).

CVE-2017-18379: Fixed an out of boundary access that happened in
drivers/nvme/target/fc.c (bsc#1145604).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1145604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18379/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14835/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192600-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c40a4d71"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2599=1 SUSE-SLE-SAP-12-SP3-2019-2600=1
SUSE-SLE-SAP-12-SP3-2019-2602=1 SUSE-SLE-SAP-12-SP3-2019-2603=1
SUSE-SLE-SAP-12-SP3-2019-2606=1 SUSE-SLE-SAP-12-SP3-2019-2607=1
SUSE-SLE-SAP-12-SP3-2019-2608=1 SUSE-SLE-SAP-12-SP3-2019-2609=1
SUSE-SLE-SAP-12-SP3-2019-2610=1 SUSE-SLE-SAP-12-SP3-2019-2611=1
SUSE-SLE-SAP-12-SP3-2019-2612=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2599=1 SUSE-SLE-SERVER-12-SP3-2019-2600=1
SUSE-SLE-SERVER-12-SP3-2019-2602=1 SUSE-SLE-SERVER-12-SP3-2019-2603=1
SUSE-SLE-SERVER-12-SP3-2019-2606=1 SUSE-SLE-SERVER-12-SP3-2019-2607=1
SUSE-SLE-SERVER-12-SP3-2019-2608=1 SUSE-SLE-SERVER-12-SP3-2019-2609=1
SUSE-SLE-SERVER-12-SP3-2019-2610=1 SUSE-SLE-SERVER-12-SP3-2019-2611=1
SUSE-SLE-SERVER-12-SP3-2019-2612=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_57-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_57-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_61-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_61-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_64-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_156-94_64-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_162-94_69-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_162-94_69-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_162-94_72-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_162-94_72-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_175-94_79-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_175-94_79-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_176-94_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_176-94_88-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_178-94_91-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_178-94_91-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_100-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_100-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_103-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_103-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_97-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_180-94_97-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/09");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_57-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_57-default-debuginfo-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_61-default-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_61-default-debuginfo-8-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_64-default-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_156-94_64-default-debuginfo-7-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_162-94_69-default-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_162-94_69-default-debuginfo-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_162-94_72-default-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_162-94_72-default-debuginfo-6-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_175-94_79-default-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_175-94_79-default-debuginfo-5-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_176-94_88-default-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_176-94_88-default-debuginfo-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_178-94_91-default-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_178-94_91-default-debuginfo-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_100-default-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_100-default-debuginfo-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_103-default-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_103-default-debuginfo-2-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_97-default-4-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"kgraft-patch-4_4_180-94_97-default-debuginfo-4-2.1")) flag++;


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
