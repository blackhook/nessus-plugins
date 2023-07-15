#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:13999-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123554);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2017-5715");

  script_name(english:"SUSE SLES11 Security Update : various KMPs (SUSE-SU-2019:13999-1) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update rebuilds missing kernel modules (KMP) to use 'retpolines'
mitigations for Spectre Variant 2 (CVE-2017-5715).

Rebuilt KMP packages :

cluster-network

drbd

gfs2

iscsitarget

ocfs2

ofed

oracleasm

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5715/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-201913999-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a51a552f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kmps-retpoline-20190320-13999=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kmps-retpoline-20190320-13999=1

SUSE Linux Enterprise Real Time Extension 11-SP4:zypper in -t patch
slertesp4-kmps-retpoline-20190320-13999=1

SUSE Linux Enterprise High Availability Extension 11-SP4:zypper in -t
patch slehasp4-kmps-retpoline-20190320-13999=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kmps-retpoline-20190320-13999=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsitarget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsitarget-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ofed-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oracleasm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oracleasm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oracleasm-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oracleasm-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oracleasm-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"ofed-kmp-default-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"ofed-kmp-trace-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"iscsitarget-kmp-xen-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"oracleasm-kmp-xen-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"iscsitarget-kmp-pae-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"ofed-kmp-pae-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"oracleasm-kmp-pae-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"iscsitarget-1.4.20-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"iscsitarget-kmp-default-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"iscsitarget-kmp-trace-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ofed-1.5.4.1-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ofed-doc-1.5.4.1-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"oracleasm-2.0.5-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"oracleasm-kmp-default-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"oracleasm-kmp-trace-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"ofed-kmp-default-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"ofed-kmp-trace-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"iscsitarget-kmp-xen-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"oracleasm-kmp-xen-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"iscsitarget-kmp-pae-1.4.20_3.0.101_108.87-0.43.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"ofed-kmp-pae-1.5.4.1_3.0.101_108.87-22.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"oracleasm-kmp-pae-2.0.5_3.0.101_108.87-7.44.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "various KMPs");
}
