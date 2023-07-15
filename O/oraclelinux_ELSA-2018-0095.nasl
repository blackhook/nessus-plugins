#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0095 and 
# Oracle Linux Security Advisory ELSA-2018-0095 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106119);
  script_version("3.7");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_xref(name:"RHSA", value:"2018:0095");

  script_name(english:"Oracle Linux 6 / 7 : java-1.8.0-openjdk (ELSA-2018-0095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0095 :

An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* Multiple flaws were found in the Hotspot and AWT components of
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2018-2582,
CVE-2018-2641)

* It was discovered that the LDAPCertStore class in the JNDI component
of OpenJDK failed to securely handle LDAP referrals. An attacker could
possibly use this flaw to make it fetch attacker controlled
certificate data. (CVE-2018-2633)

* The JGSS component of OpenJDK ignores the value of the
javax.security.auth.useSubjectCredsOnly property when using
HTTP/SPNEGO authentication and always uses global credentials. It was
discovered that this could cause global credentials to be unexpectedly
used by an untrusted Java application. (CVE-2018-2634)

* It was discovered that the JMX component of OpenJDK failed to
properly set the deserialization filter for the SingleEntryRegistry in
certain cases. A remote attacker could possibly use this flaw to
bypass intended deserialization restrictions. (CVE-2018-2637)

* It was discovered that the LDAP component of OpenJDK failed to
properly encode special characters in user names when adding them to
an LDAP search query. A remote attacker could possibly use this flaw
to manipulate LDAP queries performed by the LdapLoginModule class.
(CVE-2018-2588)

* It was discovered that the DNS client implementation in the JNDI
component of OpenJDK did not use random source ports when sending out
DNS queries. This could make it easier for a remote attacker to spoof
responses to those queries. (CVE-2018-2599)

* It was discovered that the I18n component of OpenJDK could use an
untrusted search path when loading resource bundle classes. A local
attacker could possibly use this flaw to execute arbitrary code as
another local user by making their Java application load an attacker
controlled class file. (CVE-2018-2602)

* It was discovered that the Libraries component of OpenJDK failed to
sufficiently limit the amount of memory allocated when reading DER
encoded input. A remote attacker could possibly use this flaw to make
a Java application use an excessive amount of memory if it parsed
attacker supplied DER encoded input. (CVE-2018-2603)

* It was discovered that the key agreement implementations in the JCE
component of OpenJDK did not guarantee sufficient strength of used
keys to adequately protect generated shared secret. This could make it
easier to break data encryption by attacking key agreement rather than
the encryption using the negotiated secret. (CVE-2018-2618)

* It was discovered that the JGSS component of OpenJDK failed to
properly handle GSS context in the native GSS library wrapper in
certain cases. A remote attacker could possibly make a Java
application using JGSS to use a previously freed context.
(CVE-2018-2629)

* It was discovered that multiple classes in the Libraries, AWT, and
JNDI components of OpenJDK did not sufficiently validate input when
creating object instances from the serialized form. A specially
crafted input could cause a Java application to create objects with an
inconsistent state or use an excessive amount of memory when
deserialized. (CVE-2018-2663, CVE-2018-2677, CVE-2018-2678)

* It was discovered that multiple encryption key classes in the
Libraries component of OpenJDK did not properly synchronize access to
their internal data. This could possibly cause a multi-threaded Java
application to apply weak encryption to data because of the use of a
key that was zeroed out. (CVE-2018-2579)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007460.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-demo-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-devel-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-headless-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-src-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.161-3.b14.el6_9")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.161-0.b14.el7_4")) flag++;


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
