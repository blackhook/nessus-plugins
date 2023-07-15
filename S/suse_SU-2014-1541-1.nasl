#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1541-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119959);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id(
    "CVE-2014-3065",
    "CVE-2014-3566",
    "CVE-2014-4288",
    "CVE-2014-6457",
    "CVE-2014-6458",
    "CVE-2014-6466",
    "CVE-2014-6492",
    "CVE-2014-6493",
    "CVE-2014-6502",
    "CVE-2014-6503",
    "CVE-2014-6506",
    "CVE-2014-6511",
    "CVE-2014-6512",
    "CVE-2014-6513",
    "CVE-2014-6515",
    "CVE-2014-6531",
    "CVE-2014-6532",
    "CVE-2014-6558"
  );
  script_bugtraq_id(
    70456,
    70460,
    70468,
    70470,
    70484,
    70507,
    70518,
    70533,
    70538,
    70544,
    70548,
    70556,
    70565,
    70567,
    70569,
    70572,
    70574,
    71147
  );

  script_name(english:"SUSE SLES12 Security Update : java-1_6_0-ibm (SUSE-SU-2014:1541-1) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"java-1_6_0-ibm was updated to version 1.6.0_sr16.2 to fix 18 security
issues.

These security issues were fixed :

  - Unspecified vulnerability in Oracle Java SE 6u81
    (CVE-2014-3065).

  - The SSL protocol 3.0, as used in OpenSSL through 1.0.1i
    and other products, uses nondeterministic CBC padding,
    which makes it easier for man-in-the-middle attackers to
    obtain cleartext data via a padding-oracle attack, aka
    the 'POODLE' issue (CVE-2014-3566).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, and Java SE Embedded 7u60, allows remote
    attackers to affect confidentiality, integrity, and
    availability via vectors related to AWT (CVE-2014-6513).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6532
    (CVE-2014-6503).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288, CVE-2014-6493, and CVE-2014-6503
    (CVE-2014-6532).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-6493, CVE-2014-6503, and CVE-2014-6532
    (CVE-2014-4288).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288, CVE-2014-6503, and CVE-2014-6532
    (CVE-2014-6493).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, when running on Firefox, allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment
    (CVE-2014-6492).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows local users to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Deployment (CVE-2014-6458).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, when running on Internet Explorer, allows
    local users to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment
    (CVE-2014-6466).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors related to
    Libraries (CVE-2014-6506).

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect integrity via
    unknown vectors related to Deployment (CVE-2014-6515).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20 allows remote attackers to affect
    confidentiality via unknown vectors related to 2D
    (CVE-2014-6511).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect confidentiality via unknown
    vectors related to Libraries (CVE-2014-6531).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3 and R28.3.3 allows remote attackers to affect
    integrity via unknown vectors related to Libraries
    (CVE-2014-6512).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3, and R28.3.3 allows remote attackers to affect
    confidentiality and integrity via vectors related to
    JSSE (CVE-2014-6457).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect integrity via unknown vectors
    related to Libraries (CVE-2014-6502).

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3 and JRockit R28.3.3 allows remote attackers to
    affect integrity via unknown vectors related to Security
    (CVE-2014-6558).

Further information can be found at
http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update
_Nove mber_2014

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update_Nove
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecb047de");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=901223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=901239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=904889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-3065/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-3566/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-4288/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6457/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6458/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6466/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6492/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6493/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6502/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6503/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6506/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6511/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6512/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6513/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6515/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6531/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6532/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-6558/");
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141541-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3798b6d5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Legacy Software 12 :

zypper in -t patch SUSE-SLE-Module-Legacy-12-2014-93

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6513");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr16.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-1.6.0_sr16.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-fonts-1.6.0_sr16.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_6_0-ibm-jdbc-1.6.0_sr16.2-8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-ibm");
}
