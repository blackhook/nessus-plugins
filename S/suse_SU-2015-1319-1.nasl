#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1319-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85152);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-2590",
    "CVE-2015-2596",
    "CVE-2015-2597",
    "CVE-2015-2601",
    "CVE-2015-2613",
    "CVE-2015-2619",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2627",
    "CVE-2015-2628",
    "CVE-2015-2632",
    "CVE-2015-2637",
    "CVE-2015-2638",
    "CVE-2015-2664",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4729",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4736",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    73684,
    74733,
    75784,
    75796,
    75812,
    75818,
    75823,
    75832,
    75833,
    75850,
    75854,
    75856,
    75857,
    75861,
    75867,
    75871,
    75874,
    75881,
    75883,
    75887,
    75890,
    75892,
    75893,
    75895
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2015:1319-1) (Bar Mitzvah) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"OpenJDK was updated to 2.6.1 - OpenJDK 7u85 to fix security issues and
bugs.

The following vulnerabilities were fixed :

  - CVE-2015-2590: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2596: Difficult to exploit vulnerability in the
    Hotspot component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized update, insert or delete access to some
    Java accessible data.

  - CVE-2015-2597: Easily exploitable vulnerability in the
    Install component requiring logon to Operating System.
    Successful attack of this vulnerability could have
    resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2601: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2613: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java SE, Java SE Embedded
    accessible data.

  - CVE-2015-2619: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2621: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2625: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized read
    access to a subset of Java accessible data.

  - CVE-2015-2627: Very difficult to exploit vulnerability
    in the Install component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized read access to a subset of Java
    accessible data.

  - CVE-2015-2628: Easily exploitable vulnerability in the
    CORBA component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2632: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2637: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2638: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-2664: Difficult to exploit vulnerability in the
    Deployment component requiring logon to Operating
    System. Successful attack of this vulnerability could
    have resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2808: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java
    accessible data.

  - CVE-2015-4000: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java Embedded
    accessible data.

  - CVE-2015-4729: Very difficult to exploit vulnerability
    in the Deployment component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized update, insert or delete access
    to some Java SE accessible data as well as read access
    to a subset of Java SE accessible data.

  - CVE-2015-4731: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4732: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4733: Easily exploitable vulnerability in the
    RMI component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4736: Difficult to exploit vulnerability in the
    Deployment component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4748: Very difficult to exploit vulnerability
    in the Security component allowed successful
    unauthenticated network attacks via OCSP. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4749: Difficult to exploit vulnerability in the
    JNDI component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized ability to cause a partial denial of
    service (partial DOS).

  - CVE-2015-4760: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=938248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2590/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2596/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2597/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2601/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2613/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2619/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2621/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2625/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2627/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2628/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2632/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2637/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2638/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2664/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2808/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4000/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4729/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4731/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4732/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4733/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4736/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4748/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4749/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-4760/");
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151319-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16d16647");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-352=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-352=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debugsource-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.85-18.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.85-18.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
