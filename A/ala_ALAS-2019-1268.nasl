#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1268.
#

include("compat.inc");

if (description)
{
  script_id(128291);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842");
  script_xref(name:"ALAS", value:"2019-1268");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2019-1268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Utilities). Supported versions that are
affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE
Embedded: 8u211. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks of this
vulnerability can result in unauthorized ability to cause a partial
denial of service (partial DOS) of Java SE, Java SE Embedded. Note:
This vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g., through a web service which supplies
data to the APIs. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).(CVE-2019-2769)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Networking). Supported versions that are
affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE
Embedded: 8u211. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Java SE, Java SE Embedded accessible data as well as
unauthorized read access to a subset of Java SE, Java SE Embedded
accessible data. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability can also be exploited by
using APIs in the specified Component, e.g., through a web service
which supplies data to the APIs. CVSS 3.0 Base Score 4.8
(Confidentiality and Integrity impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).(CVE-2019-2816)

Vulnerability in the Java SE component of Oracle Java SE
(subcomponent: Security). Supported versions that are affected are
Java SE: 7u221, 8u212 and 11.0.3. Difficult to exploit vulnerability
allows unauthenticated attacker with logon to the infrastructure where
Java SE executes to compromise Java SE. Successful attacks of this
vulnerability can result in unauthorized access to critical data or
complete access to all Java SE accessible data. Note: This
vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g., through a web service which supplies
data to the APIs. CVSS 3.0 Base Score 5.1 (Confidentiality impacts).
CVSS Vector:
(CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N).(CVE-2019-2745)

Vulnerability in the Java SE component of Oracle Java SE
(subcomponent: JCE). The supported version that is affected is Java
SE: 8u212. Difficult to exploit vulnerability allows unauthenticated
attacker with network access via multiple protocols to compromise Java
SE. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability can also be exploited by
using APIs in the specified Component, e.g., through a web service
which supplies data to the APIs. CVSS 3.0 Base Score 3.7 (Availability
impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).(CVE-2019-2842)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Security). Supported versions that are affected
are Java SE: 8u212, 11.0.3 and 12.0.1; Java SE Embedded: 8u211.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks require human interaction from a
person other than the attacker and while the vulnerability is in Java
SE, Java SE Embedded, attacks may significantly impact additional
products. Successful attacks of this vulnerability can result in
unauthorized read access to a subset of Java SE, Java SE Embedded
accessible data. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability can also be exploited by
using APIs in the specified Component, e.g., through a web service
which supplies data to the APIs. CVSS 3.0 Base Score 3.4
(Confidentiality impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N).(CVE-2019-2786)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Utilities). Supported versions that are
affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE
Embedded: 8u211. Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks of this
vulnerability can result in unauthorized ability to cause a partial
denial of service (partial DOS) of Java SE, Java SE Embedded. Note:
This vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g., through a web service which supplies
data to the APIs. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).(CVE-2019-2762)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1268.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.231-2.6.19.1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.231-2.6.19.1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.231-2.6.19.1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.231-2.6.19.1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.231-2.6.19.1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.231-2.6.19.1.80.amzn1")) flag++;

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
