#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0665-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(108512);
  script_version("1.5");
  script_cvs_date("Date: 2019/09/10 13:51:47");

  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2638", "CVE-2018-2639", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");

  script_name(english:"SUSE SLES12 Security Update : java-1_8_0-ibm (SUSE-SU-2018:0665-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-ibm fixes the following issues :

  - Removed java-1_8_0-ibm-alsa and java-1_8_0-ibm-plugin
    entries in baselibs.conf due to errors in osc
    source_validator Version update to 8.0.5.10
    [bsc#1082810]

  - Security fixes: CVE-2018-2639 CVE-2018-2638
    CVE-2018-2633 CVE-2018-2637 CVE-2018-2634 CVE-2018-2582
    CVE-2018-2641 CVE-2018-2618 CVE-2018-2603 CVE-2018-2599
    CVE-2018-2602 CVE-2018-2678 CVE-2018-2677 CVE-2018-2663
    CVE-2018-2588 CVE-2018-2579

  - Defect fixes :

  - IJ02608 Class Libraries: Change of namespace definitions
    with handlers that implement
    javax.xml.ws.handler.soap.soaphandler

  - IJ04280 Class Libraries: Deploy Upgrade to Oracle level
    8u161-b12

  - IJ03390 Class Libraries: JCL Upgrade to Oracle level
    8u161-b12

  - IJ04001 Class Libraries: Performance improvement with
    child process on AIX

  - IJ04281 Class Libraries: Startup time increase after
    applying apar IV96905

  - IJ03822 Class Libraries: Update timezone information to
    tzdata2017c

  - IJ03440 Java Virtual Machine: Assertion failure during
    class creation

  - IJ03717 Java Virtual Machine: Assertion for gencon with
    concurrent scavenger on ZOS64

  - IJ03513 Java Virtual Machine: Assertion in concurrent
    scavenger if initial heap memory size -Xms is set too
    low

  - IJ03994 Java Virtual Machine: Class.getmethods() does
    not return all methods

  - IJ03413 Java Virtual Machine: Hang creating thread after
    redefining classes

  - IJ03852 Java Virtual Machine: ICH408I message when
    groupaccess is specified with -xshareclasses

  - IJ03716 Java Virtual Machine: java/lang/linkageerror
    from sun/misc/unsafe.definean onymousclass()

  - IJ03116 Java Virtual Machine: java.fullversion string
    contains an extra space

  - IJ03347 Java Virtual Machine:
    java.lang.IllegalStateException in related class
    MemoryMXBean

  - IJ03878 Java Virtual Machine:
    java.lang.StackOverflowError is thrown when custom
    security manager in place

  - IJ03605 Java Virtual Machine: Legacy security for
    com.ibm.jvm.dump, trace, log was not enabled by default

  - IJ04248 JIT Compiler: ArrayIndexOutOfBoundsException is
    thrown when converting BigDecimal to String

  - IJ04250 JIT Compiler: Assertion failure with
    concurrentScavenge on Z14

  - IJ03606 JIT Compiler: Java crashes with -version

  - IJ04251 JIT Compiler: JIT compiled method that takes
    advantage of AutoSIMD produces an incorrect result on
    x86

  - IJ03854 JIT Compiler: JVM info message appears in stdout

  - IJ03607 JIT Compiler: Result String contains a redundant
    dot when converted from BigDecimal with 0 on all
    platforms

  - IX90185 ORB: Upgrade ibmcfw.jar to version O1800.01

  - IJ03715 Security: Add additional support for the
    IBMJCEPlus provider, add support for new IBMJCEPlusFIPS
    provider

  - IJ03800 Security: A fix in CMS provider for KDB
    integrity

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

  - PI93233 z/OS Extentions: Cipher.doFinal() fails when
    using AES/GCM/nopadding with AAD data of 13 bytes and a
    block size &#9; of 4081 to 4096

  - Fixes in 8.0.5.7 :

  - IJ02605 Class Libraries: Update IBM-1371 charset with
    new specification support

  - IJ02541 Java Virtual Machine: Assertions in GC when
    jvmti runs with Concurrent Scavenger

  - IJ02443 Java Virtual Machine: Committed eden region size
    is bigger than maximum eden region size

  - IJ02378 Java Virtual Machine: Existing signal action for
    SIG_IGN/SIG_DFL is not detected properly

  - IJ02758 JIT Compiler: Crash in JIT module during method
    compilation

  - IJ02733 JIT Compiler: Crash in jit module when compiling
    in non-default configuration

  - Fixes in 8.0.5.6 :

  - IJ02283 Java Virtual Machine: IllegalAccessException due
    to a missing access check for the same class in
    MethodHandle apis

  - IJ02082 Java Virtual Machine: The default value for
    class unloading kick &#9; off threshold is not set

  - IJ02018 JIT Compiler: Crash or assertion while
    attempting to acquire VM access

  - IJ02284 JIT Compiler: Division by zero in JIT compiler

  - IV88941 JIT Compiler: JIT compiler takes far too long to
    compile a method

  - IJ02285 JIT Compiler: Performance degradation during
    class unloading in Java 8 SR5

  - Support Java jnlp files run from Firefox. [bsc#1076390]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=955131"
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
    value:"https://www.suse.com/security/cve/CVE-2018-2638/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-2641/"
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
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180665-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a194104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2018-447=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-447=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2018-447=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-447=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-447=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-447=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-447=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-ibm-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-ibm-devel-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_8_0-ibm-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.10-30.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_8_0-ibm-1.8.0_sr5.10-30.16.1")) flag++;


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
