#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1509 and 
# Oracle Linux Security Advisory ELSA-2020-1509 respectively.
#

include('compat.inc');

if (description)
{
  script_id(135951);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2767",
    "CVE-2020-2773",
    "CVE-2020-2778",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2816",
    "CVE-2020-2830"
  );
  script_xref(name:"RHSA", value:"2020:1509");
  script_xref(name:"IAVA", value:"2020-A-0134-S");

  script_name(english:"Oracle Linux 7 : java-11-openjdk (ELSA-2020-1509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2020:1509 :

The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1509 advisory.

  - OpenJDK: Misplaced regular expression syntax error check
    in RegExpScanner (Scripting, 8223898) (CVE-2020-2754)

  - OpenJDK: Incorrect handling of empty string nodes in
    regular expression Parser (Scripting, 8223904)
    (CVE-2020-2755)

  - OpenJDK: Incorrect handling of references to
    uninitialized class descriptors during deserialization
    (Serialization, 8224541) (CVE-2020-2756)

  - OpenJDK: Uncaught InstantiationError exception in
    ObjectStreamClass (Serialization, 8224549)
    (CVE-2020-2757)

  - OpenJDK: Incorrect handling of Certificate messages
    during TLS handshake (JSSE, 8232581) (CVE-2020-2767)

  - OpenJDK: Unexpected exceptions raised by
    DOMKeyInfoFactory and DOMXMLSignatureFactory (Security,
    8231415) (CVE-2020-2773)

  - OpenJDK: Incomplete enforcement of algorithm
    restrictions for TLS (JSSE, 8232424) (CVE-2020-2778)

  - OpenJDK: Re-use of single TLS session for new
    connections (JSSE, 8234408) (CVE-2020-2781)

  - OpenJDK: CRLF injection into HTTP headers in HttpServer
    (Lightweight HTTP Server, 8234825) (CVE-2020-2800)

  - OpenJDK: Incorrect bounds checks in NIO Buffers
    (Libraries, 8234841) (CVE-2020-2803)

  - OpenJDK: Incorrect type checks in
    MethodType.readObject() (Libraries, 8235274)
    (CVE-2020-2805)

  - OpenJDK: Application data accepted before TLS handshake
    completion (JSSE, 8235691) (CVE-2020-2816)

  - OpenJDK: Regular expression DoS in Scanner (Concurrency,
    8236201) (CVE-2020-2830)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-April/009855.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-demo-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-devel-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-headless-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-jmods-debug-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.7.10-4.0.1.el7_8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-11-openjdk-src-debug-11.0.7.10-4.0.1.el7_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-demo / etc");
}
