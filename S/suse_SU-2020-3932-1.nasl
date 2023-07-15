#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3932-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(144599);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14798",
    "CVE-2020-14803"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLES15 Security Update : java-1_8_0-ibm (SUSE-SU-2020:3932-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_8_0-ibm fixes the following issues :

Update to Java 8.0 Service Refresh 6 Fix Pack 20
[bsc#1180063,bsc#1177943] CVE-2020-14792 CVE-2020-14797 CVE-2020-14781
CVE-2020-14779 CVE-2020-14798 CVE-2020-14796 CVE-2020-14803

  - Class libraries :

  - SOCKETADAPTOR$SOCKETINPUTSTREAM.READ is blocking for
    more time that the set timeout

  - Z/OS specific C function send_file is changing the file
    pointer position

  - Java Virtual Machine :

  - Crash on iterate java stack

  - Java process hang on SIGTERM

  - JIT Compiler :

  - JMS performance regression from JDK8 SR5 FP40 TO FP41

  - Class Libraries :

  - z15 high utilization following Z/VM and Linux migration
    from z14 To z15

  - Java Virtual Machine :

  - Assertion failed when trying to write a class file

  - Assertion failure at modronapi.cpp

  - Improve the performance of defining and finding classes

  - JIT Compiler :

  - An assert in ppcbinaryencoding.cpp may trigger when
    running with traps disabled on power

  - AOT field offset off by n bytes

  - Segmentation fault in jit module on ibm z platform

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14779/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14781/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14792/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14796/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14797/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14798/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14803/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203932-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c50fcad1");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3932=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3932=1

SUSE Linux Enterprise Module for Legacy Software 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP3-2020-3932=1

SUSE Linux Enterprise Module for Legacy Software 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP2-2020-3932=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP1-2020-3932=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"java-1_8_0-ibm-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-ibm-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-1_8_0-ibm-1.8.0_sr6.20-3.47.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"java-1_8_0-ibm-devel-1.8.0_sr6.20-3.47.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-ibm");
}
