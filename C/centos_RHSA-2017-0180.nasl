#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0180 and 
# CentOS Errata and Security Advisory 2017:0180 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96664);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");
  script_xref(name:"RHSA", value:"2017:0180");

  script_name(english:"CentOS 6 / 7 : java-1.8.0-openjdk (CESA-2017:0180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the RMI registry and DCG implementations in
the RMI component of OpenJDK performed deserialization of untrusted
inputs. A remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of RMI registry or a Java RMI
application. (CVE-2017-3241)

This issue was addressed by introducing whitelists of classes that can
be deserialized by RMI registry or DCG. These whitelists can be
customized using the newly introduced sun.rmi.registry.registryFilter
and sun.rmi.transport.dgcFilter security properties.

* Multiple flaws were discovered in the Libraries and Hotspot
components in OpenJDK. An untrusted Java application or applet could
use these flaws to completely bypass Java sandbox restrictions.
(CVE-2017-3272, CVE-2017-3289)

* A covert timing channel flaw was found in the DSA implementation in
the Libraries component of OpenJDK. A remote attacker could possibly
use this flaw to extract certain information about the used key via a
timing side channel. (CVE-2016-5548)

* It was discovered that the Libraries component of OpenJDK accepted
ECSDA signatures using non-canonical DER encoding. This could cause a
Java application to accept signature in an incorrect format not
accepted by other cryptographic tools. (CVE-2016-5546)

* It was discovered that the 2D component of OpenJDK performed parsing
of iTXt and zTXt PNG image chunks even when configured to ignore
metadata. An attacker able to make a Java application parse a
specially crafted PNG image could cause the application to consume an
excessive amount of memory. (CVE-2017-3253)

* It was discovered that the Libraries component of OpenJDK did not
validate the length of the object identifier read from the DER input
before allocating memory to store the OID. An attacker able to make a
Java application decode a specially crafted DER input could cause the
application to consume an excessive amount of memory. (CVE-2016-5547)

* It was discovered that the JAAS component of OpenJDK did not use the
correct way to extract user DN from the result of the user search LDAP
query. A specially crafted user LDAP entry could cause the application
to use an incorrect DN. (CVE-2017-3252)

* It was discovered that the Networking component of OpenJDK failed to
properly parse user info from the URL. A remote attacker could cause a
Java application to incorrectly parse an attacker supplied URL and
interpret it differently from other applications processing the same
URL. (CVE-2016-5552)

* Multiple flaws were found in the Networking components in OpenJDK.
An untrusted Java application or applet could use these flaws to
bypass certain Java sandbox restrictions. (CVE-2017-3261,
CVE-2017-3231)

* A flaw was found in the way the DES/3DES cipher was used as part of
the TLS /SSL protocol. A man-in-the-middle attacker could use this
flaw to recover some plaintext data by capturing large amounts of
encrypted traffic between TLS/SSL server and client if the
communication used a DES/3DES based ciphersuite. (CVE-2016-2183)

This update mitigates the CVE-2016-2183 issue by adding 3DES cipher
suites to the list of legacy algorithms (defined using the
jdk.tls.legacyAlgorithms security property) so they are only used if
connecting TLS/SSL client and server do not share any other non-legacy
cipher suite.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-January/022247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4577c10"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-January/022248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf441c69"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3241");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-debug-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-1.8.0.121-0.b13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.121-0.b13.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.121-0.b13.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.121-0.b13.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
