#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-936.
#

include("compat.inc");

if (description)
{
  script_id(105421);
  script_version("3.5");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");
  script_xref(name:"ALAS", value:"2017-936");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2017-936)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Security component of OpenJDK could fail to
properly enforce restrictions defined for processing of X.509
certificate chains. A remote attacker could possibly use this flaw to
make Java accept certificate using one of the disabled algorithms.
(CVE-2017-10198)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Hotspot). Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded. Successful attacks
require human interaction from a person other than the attacker and
while the vulnerability is in Java SE, Java SE Embedded, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in takeover of Java SE, Java SE Embedded.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2017-10346)

Vulnerability in the Java SE, JRockit component of Oracle Java SE
(subcomponent: Serialization). Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, JRockit. Successful attacks of this vulnerability
can result in unauthorized ability to cause a partial denial of
service (partial DOS) of Java SE, JRockit. Note: This vulnerability
applies to Java deployments, typically in clients running sandboxed
Java Web Start applications or sandboxed Java applets, that load and
run untrusted code (e.g., code that comes from the internet) and rely
on the Java sandbox for security. This vulnerability does not apply to
Java deployments, typically in servers, that load and run only trusted
code (e.g., code installed by an administrator). (CVE-2017-10347)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Serialization). Easily exploitable
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, Java SE Embedded. Successful
attacks of this vulnerability can result in unauthorized ability to
cause a partial denial of service (partial DOS) of Java SE, Java SE
Embedded. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets, that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability does not apply to Java deployments,
typically in servers, that load and run only trusted code (e.g., code
installed by an administrator). (CVE-2017-10357)

It was discovered that the Security component of OpenJDK generated
weak password-based encryption keys used to protect private keys
stored in key stores. This made it easier to perform password guessing
attacks to decrypt stored keys if an attacker could gain access to a
key store. (CVE-2017-10356)

It was found that the FtpClient implementation in the Networking
component of OpenJDK did not set connect and read timeouts by default.
A malicious FTP server or a man-in-the-middle attacker could use this
flaw to block execution of a Java application connecting to an FTP
server. (CVE-2017-10355)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Serialization). Difficult to exploit
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, Java SE Embedded, JRockit.
Successful attacks require human interaction from a person other than
the attacker. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability
can be exploited through sandboxed Java Web Start applications and
sandboxed Java applets. It can also be exploited by supplying data to
APIs in the specified Component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a web service.
(CVE-2017-10345)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Security). Difficult to exploit vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded. Successful attacks
require human interaction from a person other than the attacker.
Successful attacks of this vulnerability can result in unauthorized
read access to a subset of Java SE, Java SE Embedded accessible data.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2017-10193)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Libraries). Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded. Successful attacks
of this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2017-10348)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: JAXP). Supported versions that are affected are
Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
exploitable vulnerability allows unauthenticated attacker with network
access via multiple protocols to compromise Java SE, Java SE Embedded.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded. Note: This vulnerability applies to Java
deployments, typically in clients running sandboxed Java Web Start
applications or sandboxed Java applets, that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability does not apply to Java
deployments, typically in servers, that load and run only trusted code
(e.g., code installed by an administrator). (CVE-2017-10349)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: JAX-WS). Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded. Successful attacks
of this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2017-10350)

Vulnerability in the Java SE component of Oracle Java SE
(subcomponent: Smart Card IO). Difficult to exploit vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized creation, deletion or
modification access to critical data or all Java SE accessible data as
well as unauthorized access to critical data or complete access to all
Java SE accessible data. Note: This vulnerability applies to Java
deployments, typically in clients running sandboxed Java Web Start
applications or sandboxed Java applets, that load and run untrusted
code (e.g., code that comes from the internet) and rely on the Java
sandbox for security. This vulnerability does not apply to Java
deployments, typically in servers, that load and run only trusted code
(e.g., code installed by an administrator). (CVE-2017-10274)

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Serialization). Easily exploitable
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, Java SE Embedded, JRockit.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE,
Java SE Embedded, JRockit. Note: This vulnerability can be exploited
through sandboxed Java Web Start applications and sandboxed Java
applets. It can also be exploited by supplying data to APIs in the
specified Component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a web service.
(CVE-2017-10281)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: RMI). Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks require human
interaction from a person other than the attacker and while the
vulnerability is in Java SE, Java SE Embedded, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in takeover of Java SE, Java SE Embedded.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2017-10285)

It was found that the HttpURLConnection and HttpsURLConnection classes
in the Networking component of OpenJDK failed to check for newline
characters embedded in URLs. An attacker able to make a Java
application perform an HTTP request using an attacker provided URL
could possibly inject additional headers into the request.
(CVE-2017-10295)

It was discovered that the Kerberos client implementation in the
Libraries component of OpenJDK used the sname field from the plain
text part rather than encrypted part of the KDC reply message. A
man-in-the-middle attacker could possibly use this flaw to impersonate
Kerberos services to Java applications acting as Kerberos clients.
(CVE-2017-10388)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-936.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.161-2.6.12.0.75.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.161-2.6.12.0.75.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.161-2.6.12.0.75.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.161-2.6.12.0.75.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.161-2.6.12.0.75.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.161-2.6.12.0.75.amzn1")) flag++;

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
