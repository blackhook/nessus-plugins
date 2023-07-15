#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3868-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(120167);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/16");

  script_cve_id("CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214");

  script_name(english:"SUSE SLES15 Security Update : java-1_8_0-ibm (SUSE-SU-2018:3868-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_8_0-ibm was updated to Java 8.0 Service Refresh 5 Fix Pack 25
(bsc#1116574)

Class Libraries :

  - IJ10934 CVE-2018-13785

  - IJ10935 CVE-2018-3136

  - IJ10895 CVE-2018-3139

  - IJ10932 CVE-2018-3149

  - IJ10894 CVE-2018-3180

  - IJ10930 CVE-2018-3183

  - IJ10933 CVE-2018-3214

  - IJ09315 FLOATING POINT EXCEPTION FROM
    JAVA.TEXT.DECIMALFORMAT. FORMAT

  - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE
    FOR PRODUCTS NOT IDENTIFYING TRT

  - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM
    JDK&Atilde;&cent;&Acirc;&#128;&Acirc;&#153;S CACERTS.

  - IJ10566 SUPPORT EBCDIC CODE PAGE IBM-274
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147; BELGIUM EBCDIC
    Java Virtual Machine

  - IJ08730 APPLICATION SIGNAL HANDLER NOT INVOKED FOR
    SIGABRT

  - IJ10453 ASSERTION FAILURE AT CLASSPATHITEM.CPP

  - IJ09574 CLASSLOADER DEFINED THROUGH SYSTEM PROPERTY
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#152;JAVA.SYSTEM.CLAS
    S.LOADE R&Atilde;&cent;&Acirc;&#128;&Acirc;&#153; IS NOT
    HONORED.

  - IJ10931 CVE-2018-3169

  - IJ10618 GPU SORT: UNSPECIFIED LAUNCH FAILURE

  - IJ10619 INCORRECT ILLEGALARGUMENTEXCEPTION BECAUSE
    OBJECT IS NOT AN INSTANCE OF DECLARING CLASS ON
    REFLECTIVE INVOCATION

  - IJ10135 JVM HUNG IN GARBAGECOLLECTORMXBEAN.G
    ETLASTGCINFO() API

  - IJ10680 RECURRENT ABORTED SCAVENGE ORB

  - IX90187 CLIENTREQUESTIMPL.REINVO KE FAILS WITH
    JAVA.LANG.INDEXOUTOFBOUN DSEXCEPTION Reliability and
    Serviceability

  - IJ09600 DTFJ AND JDMPVIEW FAIL TO PARSE WIDE REGISTER
    VALUES Security

  - IJ10492 'EC KEYSIZE z/OS Extentions

  - PH03889 ADD SUPPORT FOR TRY-WITH-RESOURCES TO
    COM.IBM.JZOS.ENQUEUE

  - PH03414 ROLLOVER FROM SYE TO SAE FOR ICSF REASON CODE
    3059

  - PH04008 ZERTJSSE
    &Atilde;&cent;&Acirc;&#128;&Acirc;&#147; Z SYSTEMS
    ENCRYPTION READINESS TOOL (ZERT) NEW SUPPORT IN THE Z/OS
    JAVA SDK

This includes the update to Java 8.0 Service Refresh 5 Fix Pack 22:
Java Virtual Machine

  - IJ09139 CUDA4J NOT AVAILABLE ON ALL PLATFORMS JIT
    Compiler

  - IJ09089 CRASH DURING COMPILATION IN USEREGISTER ON
    X86-32

  - IJ08655 FLOATING POINT ERROR (SIGFPE) IN ZJ9SYM1 OR ANY
    VM/JIT MODULE ON AN INSTRUCTION FOLLOWING A VECTOR
    INSTRUCTION

  - IJ08850 CRASH IN ARRAYLIST$ITR.NEXT()

  - IJ09601 JVM CRASHES ON A SIGBUS SIGNAL WHEN ACCESSING A
    DIRECTBYTEBUFFER z/OS Extentions

  - PH02999 JZOS data management classes accept dataset
    names in code pages supported by z/OS system services

  - PH01244 OUTPUT BUFFER TOO SHORT FOR GCM MODE ENCRYPTION
    USING IBMJCEHYBRID

Also the update to Java 8.0 Service Refresh 5 Fix Pack 21 Class
Libraries

  - IJ08569 JAVA.IO.IOEXCEPTION OCCURS WHEN A FILECHANNEL IS
    BIGGER THAN 2GB ON AIX PLATFORM

  - IJ08570 JAVA.LANG.UNSATISFIEDLIN KERROR WITH JAVA OPTION

    -DSUN.JAVA2D.CMM=SUN.JAV A2D.CMM.KCMS.KCMSSERVICE
    PROVIDER ON AIX PLATFORM Java Virtual Machine

  - IJ08001 30% THROUGHPUT DROP FOR CERTAIN SYNCHRONIZATION
    WORKLOADS

  - IJ07997 TRACEASSERT IN GARBAGE COLLECTOR(MEMORYSUBSPACE)
    JIT Compiler

  - IJ08503 ASSERTION IS HIT DUE TO UNEXPECTED STACK HEIGHT
    IN DEBUGGING MODE

  - IJ08375 CRASH DURING HARDWARE GENERATED GUARDED STORAGE
    EVENT WITHIN A TRANSACTIONAL EXECUTION REGION WHEN
    RUNNING WITH -XGC:CONCURRENTS

  - IJ08205 CRASH WHILE COMPILING

  - IJ09575 INCORRECT RESULT WHEN USING JAVA.LANG.MATH.MIN
    OR MAX ON 31-BIT JVM

  - IJ07886 INCORRECT CALUCATIONS WHEN USING
    NUMBERFORMAT.FORMAT() AND BIGDECIMAL.{FLOAT/DOUBLE
    }VALUE()

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-13785/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3136/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3139/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3149/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3169/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3180/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3183/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3214/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183868-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0baaa4a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Legacy Software 15:zypper in -t patch
SUSE-SLE-Module-Legacy-15-2018-2763=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"java-1_8_0-ibm-alsa-1.8.0_sr5.25-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"java-1_8_0-ibm-plugin-1.8.0_sr5.25-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-1_8_0-ibm-1.8.0_sr5.25-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"java-1_8_0-ibm-devel-1.8.0_sr5.25-3.9.1")) flag++;


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
