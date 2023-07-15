#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2548-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103415);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000251");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2017:2548-1) (BlueBorne)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive the
following security fixes :

  - CVE-2017-1000251: The native Bluetooth stack in the
    Linux Kernel was vulnerable to a stack overflow while
    processing L2CAP configuration responses, resulting in a
    potential remote code execution vulnerability.
    [bnc#1057389]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-1000251/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172548-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?340f7c9b"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-source-13286=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-source-13286=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-source-13286=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-source-13286=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-108.10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-108.10.1")) flag++;


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
