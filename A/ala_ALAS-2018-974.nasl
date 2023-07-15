#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-974.
#

include("compat.inc");

if (description)
{
  script_id(108599);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2018-2579", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_xref(name:"ALAS", value:"2018-974");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2018-974)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DerValue unbounded memory allocation :

It was discovered that the Libraries component of OpenJDK failed to
sufficiently limit the amount of memory allocated when reading DER
encoded input. A remote attacker could possibly use this flaw to make
a Java application use an excessive amount of memory if it parsed
attacker supplied DER encoded input. (CVE-2018-2603)

Unsynchronized access to encryption key data

It was discovered that multiple encryption key classes in the
Libraries component of OpenJDK did not properly synchronize access to
their internal data. This could possibly cause a multi-threaded Java
application to apply weak encryption to data because of the use of a
key that was zeroed out. (CVE-2018-2579)

Use of global credentials for HTTP/SPNEGO

The JGSS component of OpenJDK ignores the value of the
javax.security.auth.useSubjectCredsOnly property when using
HTTP/SPNEGO authentication and always uses global credentials. It was
discovered that this could cause global credentials to be unexpectedly
used by an untrusted Java application. (CVE-2018-2634)

Loading of classes from untrusted locations :

It was discovered that the I18n component of OpenJDK could use an
untrusted search path when loading resource bundle classes. A local
attacker could possibly use this flaw to execute arbitrary code as
another local user by making their Java application load an attacker
controlled class file. (CVE-2018-2602)

GTK library loading use-after-free :

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: AWT). Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks require human
interaction from a person other than the attacker and while the
vulnerability is in Java SE, Java SE Embedded, attacks may
significantly impact additional products. Successful attacks of this
vulnerability can result in unauthorized creation, deletion or
modification access to critical data or all Java SE, Java SE Embedded
accessible data. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets, that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability does not apply to Java deployments,
typically in servers, that load and run only trusted code (e.g., code
installed by an administrator). (CVE-2018-2641)

LdapLoginModule insufficient username encoding in LDAP query :

It was discovered that the LDAP component of OpenJDK failed to
properly encode special characters in user names when adding them to
an LDAP search query. A remote attacker could possibly use this flaw
to manipulate LDAP queries performed by the LdapLoginModule class.
(CVE-2018-2588)

SingleEntryRegistry incorrect setup of deserialization filter :

It was discovered that the JMX component of OpenJDK failed to properly
set the deserialization filter for the SingleEntryRegistry in certain
cases. A remote attacker could possibly use this flaw to bypass
intended deserialization restrictions. (CVE-2018-2637)

Insufficient strength of key agreement :

It was discovered that the key agreement implementations in the JCE
component of OpenJDK did not guarantee sufficient strength of used
keys to adequately protect generated shared secret. This could make it
easier to break data encryption by attacking key agreement rather than
the encryption using the negotiated secret. (CVE-2018-2618)

GSS context use-after-free :

It was discovered that the JGSS component of OpenJDK failed to
properly handle GSS context in the native GSS library wrapper in
certain cases. A remote attacker could possibly make a Java
application using JGSS to use a previously freed context.
(CVE-2018-2629)

LDAPCertStore insecure handling of LDAP referrals :

It was discovered that the LDAPCertStore class in the JNDI component
of OpenJDK failed to securely handle LDAP referrals. An attacker could
possibly use this flaw to make it fetch attacker controlled
certificate data. (CVE-2018-2633)

DnsClient missing source port randomization :

It was discovered that the DNS client implementation in the JNDI
component of OpenJDK did not use random source ports when sending out
DNS queries. This could make it easier for a remote attacker to spoof
responses to those queries. (CVE-2018-2599)

Unbounded memory allocation in BasicAttributes deserialization :

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: JNDI). Easily exploitable vulnerability
allows unauthenticated attacker with network access via multiple
protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
attacks require human interaction from a person other than the
attacker. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability
applies to client and server deployment of Java. This vulnerability
can be exploited through sandboxed Java Web Start applications and
sandboxed Java applets. It can also be exploited by supplying data to
APIs in the specified Component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a web service.
(CVE-2018-2678)

ArrayBlockingQueue deserialization to an inconsistent state :

Vulnerability in the Java SE, Java SE Embedded, JRockit component of
Oracle Java SE (subcomponent: Libraries). Easily exploitable
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE, Java SE Embedded, JRockit.
Successful attacks require human interaction from a person other than
the attacker. Successful attacks of this vulnerability can result in
unauthorized ability to cause a partial denial of service (partial
DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability
applies to client and server deployment of Java. This vulnerability
can be exploited through sandboxed Java Web Start applications and
sandboxed Java applets. It can also be exploited by supplying data to
APIs in the specified Component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a web service.
(CVE-2018-2663)

Unbounded memory allocation during deserialization :

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: AWT). Easily exploitable vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE, Java SE Embedded. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized ability to cause a
partial denial of service (partial DOS) of Java SE, Java SE Embedded.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed
Java applets, that load and run untrusted code (e.g., code that comes
from the internet) and rely on the Java sandbox for security. This
vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2018-2677)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-974.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.171-2.6.13.0.76.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.171-2.6.13.0.76.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.171-2.6.13.0.76.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.171-2.6.13.0.76.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.171-2.6.13.0.76.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.171-2.6.13.0.76.amzn1")) flag++;

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
