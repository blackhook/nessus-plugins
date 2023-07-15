#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0630-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107213);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2657", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");

  script_name(english:"SUSE SLES11 Security Update : java-1_7_1-ibm (SUSE-SU-2018:0630-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_1-ibm provides the following fix: The version
was updated to 7.1.4.20 [bsc#1082810]

  - Security fixes :

  - CVE-2018-2633 CVE-2018-2637 CVE-2018-2634 CVE-2018-2582
    CVE-2018-2641 CVE-2018-2618 CVE-2018-2657 CVE-2018-2603
    CVE-2018-2599 CVE-2018-2602 CVE-2018-2678 CVE-2018-2677
    CVE-2018-2663 CVE-2018-2588 CVE-2018-2579

  - Defect fixes :

  - IJ04281 Class Libraries: Startup time increase after
    applying apar IV96905

  - IJ03822 Class Libraries: Update timezone information to
    tzdata2017c

  - IJ03605 Java Virtual Machine: Legacy security for
    com.ibm.jvm.dump, trace, log was not enabled by default

  - IJ03607 JIT Compiler: Result String contains a redundant
    dot when converted from BigDecimal with 0 on all
    platforms

  - IX90185 ORB: Upgrade ibmcfw.jar to version O1800.01

  - IJ04282 Security: Change in location and default of
    jurisdiction policy files

  - IJ03853 Security: IBMCAC provider does not support
    SHA224

  - IJ02679 Security: IBMPKCS11Impl
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147; Bad sessions
    are being allocated internally

  - IJ02706 Security: IBMPKCS11Impl
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147; Bad sessions
    are being allocated internally

  - IJ03552 Security: IBMPKCS11Impl - Config file problem
    with the slot specification attribute

  - IJ01901 Security: IBMPKCS11Impl
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147;
    SecureRandom.setSeed() exception

  - IJ03801 Security: Issue with same DN certs, iKeyman GUI
    error with stash, JKS Chain issue and JVM argument parse
    issue with iKeyman

  - IJ03256 Security: javax.security.auth.Subject.toString()
    throws NPE

  - IJ02284 JIT Compiler: Division by zero in JIT compiler

  - Make it possible to run Java jnlp files from Firefox.
    (bsc#1057460)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2579/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2582/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2588/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2599/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2602/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2603/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2618/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2633/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2634/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2637/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2641/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2657/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2663/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2677/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2678/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180630-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d88d6af2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-java-1_7_1-ibm-13500=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-java-1_7_1-ibm-13500=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.20-26.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.20-26.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"java-1_7_1-ibm-1.7.1_sr4.20-26.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.20-26.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.20-26.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.20-26.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_1-ibm");
}
