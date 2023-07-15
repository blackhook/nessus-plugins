#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1365.
#

include('compat.inc');

if (description)
{
  script_id(136626);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2773",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2830"
  );
  script_xref(name:"ALAS", value:"2020-1365");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2020-1365)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
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
(CVE-2020-2800)

A flaw was found in the boundary checks in the java.nio buffer classes
in the Libraries component of OpenJDK, where it is bypassed in certain
cases. This flaw allows an untrusted Java application or applet o
bypass Java sandbox restrictions. (CVE-2020-2803)

A flaw was found in the way the readObject() method of the MethodType
class in the Libraries component of OpenJDK checked argument types.
This flaw allows an untrusted Java application or applet to bypass
Java sandbox restrictions. (CVE-2020-2805)

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
(CVE-2020-2830)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1365.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update java-1.7.0-openjdk' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2800");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.261-2.6.22.1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.261-2.6.22.1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.261-2.6.22.1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.261-2.6.22.1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.261-2.6.22.1.83.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.261-2.6.22.1.83.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
