#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1421.
#

include('compat.inc');

if (description)
{
  script_id(136364);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2773",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2830"
  );
  script_xref(name:"ALAS", value:"2020-1421");

  script_name(english:"Amazon Linux 2 : java-1.8.0-openjdk (ALAS-2020-1421)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Serialization). Supported versions that are affected
are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded. Note: Applies to client and server
deployment of Java. This vulnerability can be exploited through
sandboxed Java Web Start applications and sandboxed Java applets. It
can also be exploited by supplying data to APIs in the specified
Component without using sandboxed Java Web Start applications or
sandboxed Java applets, such as through a web service. CVSS 3.0 Base
Score 3.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-2756)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Scripting). Supported versions that are affected are
Java SE: 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Difficult to
exploit vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. CVSS 3.0 Base Score 3.7 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
(CVE-2020-2755)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Concurrency). Supported versions that are affected are
Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Easily
exploitable vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. CVSS 3.0 Base Score 5.3 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
(CVE-2020-2830)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Libraries). Supported versions that are affected are
Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks require human interaction from a
person other than the attacker and while the vulnerability is in Java
SE, Java SE Embedded, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in
takeover of Java SE, Java SE Embedded. Note: This vulnerability
applies to Java deployments, typically in clients running sandboxed
Java Web Start applications or sandboxed Java applets, that load and
run untrusted code (e.g., code that comes from the internet) and rely
on the Java sandbox for security. This vulnerability does not apply to
Java deployments, typically in servers, that load and run only trusted
code (e.g., code installed by an administrator). CVSS 3.0 Base Score
8.3 (Confidentiality, Integrity and Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
(CVE-2020-2803)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Scripting). Supported versions that are affected are
Java SE: 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Difficult to
exploit vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. CVSS 3.0 Base Score 3.7 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
(CVE-2020-2754)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: JSSE). Supported versions that are affected are Java
SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Easily
exploitable vulnerability allows unauthenticated attacker with network
access via HTTPS to compromise Java SE, Java SE Embedded. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a partial denial of service (partial DOS) of Java SE, Java SE
Embedded. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. CVSS 3.0 Base Score 5.3 (Availability
impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
(CVE-2020-2781)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Lightweight HTTP Server). Supported versions that are
affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded:
8u241. Difficult to exploit vulnerability allows unauthenticated
attacker with network access via multiple protocols to compromise Java
SE, Java SE Embedded. Successful attacks of this vulnerability can
result in unauthorized update, insert or delete access to some of Java
SE, Java SE Embedded accessible data as well as unauthorized read
access to a subset of Java SE, Java SE Embedded accessible data. Note:
This vulnerability can only be exploited by supplying data to APIs in
the specified Component without using Untrusted Java Web Start
applications or Untrusted Java applets, such as through a web service.
CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Security). Supported versions that are affected are
Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded. Note: Applies to client and server
deployment of Java. This vulnerability can be exploited through
sandboxed Java Web Start applications and sandboxed Java applets. It
can also be exploited by supplying data to APIs in the specified
Component without using sandboxed Java Web Start applications or
sandboxed Java applets, such as through a web service. CVSS 3.0 Base
Score 3.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-2773)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Serialization). Supported versions that are affected
are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded. Note: Applies to client and server
deployment of Java. This vulnerability can be exploited through
sandboxed Java Web Start applications and sandboxed Java applets. It
can also be exploited by supplying data to APIs in the specified
Component without using sandboxed Java Web Start applications or
sandboxed Java applets, such as through a web service. CVSS 3.0 Base
Score 3.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-2773)

Vulnerability in the Java SE, Java SE Embedded product of Oracle Java
SE (component: Serialization). Supported versions that are affected
are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded. Note: Applies to client and server
deployment of Java. This vulnerability can be exploited through
sandboxed Java Web Start applications and sandboxed Java applets. It
can also be exploited by supplying data to APIs in the specified
Component without using sandboxed Java Web Start applications or
sandboxed Java applets, such as through a web service. CVSS 3.0 Base
Score 3.7 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2020-2757)

A flaw was found in the way the readObject() method of the MethodType
class in the Libraries component of OpenJDK checked argument types.
This flaw allows an untrusted Java application or applet to bypass
Java sandbox restrictions. (CVE-2020-2805)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1421.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.8.0-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-accessibility-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-demo-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-devel-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-headless-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-src-1.8.0.252.b09-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-src-debug-1.8.0.252.b09-2.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
