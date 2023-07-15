#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3920-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119281);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3214");

  script_name(english:"SUSE SLES11 Security Update : java-1_7_0-ibm (SUSE-SU-2018:3920-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"java-1_7_0-ibm is updated to Java 7.0 Service Refresh 10 Fix Pack 35
(bsc#1116574) :

Class Libraries

  - IJ10934 CVE-2018-13785

  - IJ10935 CVE-2018-3136

  - IJ10895 CVE-2018-3139

  - IJ10932 CVE-2018-3149

  - IJ10894 CVE-2018-3180

  - IJ10933 CVE-2018-3214

  - IJ09315 FLOATING POINT EXCEPTION FROM
    JAVA.TEXT.DECIMALFORMAT. FORMAT

  - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE
    FOR PRODUCTS NOT IDENTIFYING TRT

  - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM
    JDK&Atilde;&cent;&Acirc;&#128;&Acirc;&#153;S CACERTS
    Java Virtual Machine

  - IJ10931 CVE-2018-3169 JIT Compiler

  - IJ08205 CRASH WHILE COMPILING Security

  - IJ10492 'EC KEYSIZE

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
    value:"https://www.suse.com/security/cve/CVE-2018-3214/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183920-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db1fb79c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-java-1_7_0-ibm-13882=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-java-1_7_0-ibm-13882=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3180");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-devel-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr10.35-65.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr10.35-65.31.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-ibm");
}
