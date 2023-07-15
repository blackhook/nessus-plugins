#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1509 and 
# CentOS Errata and Security Advisory 2020:1509 respectively.
#

include('compat.inc');

if (description)
{
  script_id(136196);
  script_version("1.4");
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

  script_name(english:"CentOS 7 : java-11-openjdk (CESA-2020:1509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
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
  # https://lists.centos.org/pipermail/centos-announce/2020-April/035705.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91ebf70d");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.7.10-4.el7_8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.7.10-4.el7_8")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc");
}
