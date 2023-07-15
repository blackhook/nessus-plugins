#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1002.
#

include("compat.inc");

if (description)
{
  script_id(109363);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");
  script_xref(name:"ALAS", value:"2018-1002");

  script_name(english:"Amazon Linux 2 : java-1.8.0-openjdk (ALAS-2018-1002)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Unbounded memory allocation during deserialization in Container (AWT,
8189989)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: AWT). Supported versions that are
affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded:
8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. (CVE-2018-2798)

Unbounded memory allocation during deserialization in StubIORImpl
(Serialization, 8192757)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Serialization). Supported versions that
are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE
Embedded: 8u161; JRockit: R28.3.17. Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a partial denial of service (partial DOS) of Java SE, Java SE
Embedded, JRockit. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. (CVE-2018-2815)

Unrestricted deserialization of data from JCEKS key stores (Security,
8189997)

Vulnerability in the Java SE, JRockit component of Oracle Java SE
(subcomponent: Security). Supported versions that are affected are
Java SE: 6u181, 7u171, 8u162, 10 and JRockit: R28.3.17. Difficult to
exploit vulnerability allows unauthenticated attacker with logon to
the infrastructure where Java SE, JRockit executes to compromise Java
SE, JRockit. Successful attacks require human interaction from a
person other than the attacker and while the vulnerability is in Java
SE, JRockit, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of
Java SE, JRockit. Note: Applies to client and server deployment of
Java. This vulnerability can be exploited through sandboxed Java Web
Start applications and sandboxed Java applets. It can also be
exploited by supplying data to APIs in the specified Component without
using sandboxed Java Web Start applications or sandboxed Java applets,
such as through a web service. (CVE-2018-2794)

Insufficient consistency checks in deserialization of multiple classes
(Security, 8189977)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Security). Supported versions that are
affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded:
8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. (CVE-2018-2795)

Unbounded memory allocation during deserialization in NamedNodeMapImpl
(JAXP, 8189993)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: JAXP). Supported versions that are
affected are Java SE: 7u171, 8u162 and 10; Java SE Embedded: 8u161;
JRockit: R28.3.17. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. (CVE-2018-2799)

RMI HTTP transport enabled by default (RMI, 8193833)

Vulnerability in the Java SE, JRockit component of Oracle Java SE
(subcomponent: RMI). Supported versions that are affected are Java SE:
6u181, 7u171 and 8u162; JRockit: R28.3.17. Difficult to exploit
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, JRockit. Successful attacks
require human interaction from a person other than the attacker.
Successful attacks of this vulnerability can result in unauthorized
update, insert or delete access to some of Java SE, JRockit accessible
data as well as unauthorized read access to a subset of Java SE,
JRockit accessible data. Note: This vulnerability can only be
exploited by supplying data to APIs in the specified Component without
using Untrusted Java Web Start applications or Untrusted Java applets,
such as through a web service. (CVE-2018-2800)

Incorrect handling of Reference clones can lead to sandbox bypass
(Hotspot, 8192025)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Hotspot). Supported versions that are affected
are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161.
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
code (e.g., code installed by an administrator). (CVE-2018-2814)

Unbounded memory allocation during deserialization in
TabularDataSupport (JMX, 8189985)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: JMX). Supported versions that are
affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded:
8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. (CVE-2018-2797)

Incorrect merging of sections in the JAR manifest (Security, 8189969)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Security). Supported versions that are affected
are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks require human interaction from a
person other than the attacker. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Java SE, Java SE Embedded accessible data. Note:
This vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets, that load and run untrusted code (e.g., code that comes from
the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2018-2790)

Unbounded memory allocation during deserialization in
PriorityBlockingQueue (Concurrency, 8189981)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Concurrency). Supported versions that
are affected are Java SE: 7u171, 8u162 and 10; Java SE Embedded:
8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: Applies to client and server deployment of Java. This
vulnerability can be exploited through sandboxed Java Web Start
applications and sandboxed Java applets. It can also be exploited by
supplying data to APIs in the specified Component without using
sandboxed Java Web Start applications or sandboxed Java applets, such
as through a web service. (CVE-2018-2796)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1002.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.171-7.b10.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.171-7.b10.amzn2")) flag++;

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
