#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1097.
#

include("compat.inc");

if (description)
{
  script_id(118404);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/04");

  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183", "CVE-2018-3214");
  script_xref(name:"ALAS", value:"2018-1097");

  script_name(english:"Amazon Linux 2 : java-1.8.0-openjdk (ALAS-2018-1097)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Networking). Supported versions that are
affected are Java SE: 6u201, 7u191, 8u182 and 11; Java SE Embedded:
8u181. Difficult to exploit vulnerability allows unauthenticated
attacker with network access via multiple protocols to compromise Java
SE, Java SE Embedded. Successful attacks require human interaction
from a person other than the attacker. Successful attacks of this
vulnerability can result in unauthorized read access to a subset of
Java SE, Java SE Embedded accessible data. Note: This vulnerability
applies to Java deployments, typically in clients running sandboxed
Java Web Start applications or sandboxed Java applets (in Java SE 8),
that load and run untrusted code (e.g. code that comes from the
internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g. code installed by
an administrator). CVSS 3.0 Base Score 3.1 (Confidentiality impacts).
CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N).(CVE-2018-3139)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Sound). Supported versions that are
affected are Java SE: 6u201, 7u191 and 8u182; Java SE Embedded: 8u181;
JRockit: R28.3.19. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks of
this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability can also be exploited by
using APIs in the specified Component, e.g. through a web service
which supplies data to the APIs. CVSS 3.0 Base Score 5.3 (Availability
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).(CVE-2018-3214)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Hotspot). Supported versions that are affected
are Java SE: 7u191, 8u182 and 11; Java SE Embedded: 8u181. Difficult
to exploit vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded.
Successful attacks require human interaction from a person other than
the attacker and while the vulnerability is in Java SE, Java SE
Embedded, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in takeover of
Java SE, Java SE Embedded. Note: This vulnerability applies to Java
deployments, typically in clients running sandboxed Java Web Start
applications or sandboxed Java applets (in Java SE 8), that load and
run untrusted code (e.g. code that comes from the internet) and rely
on the Java sandbox for security. This vulnerability does not apply to
Java deployments, typically in servers, that load and run only trusted
code (e.g. code installed by an administrator). CVSS 3.0 Base Score
8.3 (Confidentiality, Integrity and Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).(CVE-2018-3169)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Scripting). Supported versions that are
affected are Java SE: 8u182 and 11; Java SE Embedded: 8u181; JRockit:
R28.3.19. Difficult to exploit vulnerability allows unauthenticated
attacker with network access via multiple protocols to compromise Java
SE, Java SE Embedded, JRockit. While the vulnerability is in Java SE,
Java SE Embedded, JRockit, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in
takeover of Java SE, Java SE Embedded, JRockit. Note: This
vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g. code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g. through a web service which supplies
data to the APIs. CVSS 3.0 Base Score 9.0 (Confidentiality, Integrity
and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H).(CVE-2018-3183)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: JSSE). Supported versions that are
affected are Java SE: 6u201, 7u191, 8u182 and 11; Java SE Embedded:
8u181; JRockit: R28.3.19. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via SSL/TLS to compromise
Java SE, Java SE Embedded, JRockit. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Java SE, Java SE Embedded, JRockit accessible data
as well as unauthorized read access to a subset of Java SE, Java SE
Embedded, JRockit accessible data and unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded,
JRockit. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted
code (e.g. code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability can also be exploited by
using APIs in the specified Component, e.g. through a web service
which supplies data to the APIs. CVSS 3.0 Base Score 5.6
(Confidentiality, Integrity and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L).(CVE-2018-3180)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: JNDI). Supported versions that are
affected are Java SE: 6u201, 7u191, 8u182 and 11; Java SE Embedded:
8u181; JRockit: R28.3.19. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded, JRockit. Successful attacks
require human interaction from a person other than the attacker and
while the vulnerability is in Java SE, Java SE Embedded, JRockit,
attacks may significantly impact additional products. Successful
attacks of this vulnerability can result in takeover of Java SE, Java
SE Embedded, JRockit. Note: This vulnerability applies to Java
deployments, typically in clients running sandboxed Java Web Start
applications or sandboxed Java applets (in Java SE 8), that load and
run untrusted code (e.g. code that comes from the internet) and rely
on the Java sandbox for security. This vulnerability can also be
exploited by using APIs in the specified Component, e.g. through a web
service which supplies data to the APIs. CVSS 3.0 Base Score 8.3
(Confidentiality, Integrity and Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).(CVE-2018-3149)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Security). Supported versions that are affected
are Java SE: 6u201, 7u191, 8u182 and 11; Java SE Embedded: 8u181.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks require human interaction from a
person other than the attacker and while the vulnerability is in Java
SE, Java SE Embedded, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in
unauthorized update, insert or delete access to some of Java SE, Java
SE Embedded accessible data. Note: This vulnerability applies to Java
deployments, typically in clients running sandboxed Java Web Start
applications or sandboxed Java applets (in Java SE 8), that load and
run untrusted code (e.g. code that comes from the internet) and rely
on the Java sandbox for security. This vulnerability does not apply to
Java deployments, typically in servers, that load and run only trusted
code (e.g. code installed by an administrator). CVSS 3.0 Base Score
3.4 (Integrity impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N).(CVE-2018-3136)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1097.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3183");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-accessibility-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-demo-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-devel-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-headless-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-src-1.8.0.191.b12-0.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"java-1.8.0-openjdk-src-debug-1.8.0.191.b12-0.amzn2")) flag++;

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
