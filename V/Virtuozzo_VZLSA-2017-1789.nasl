#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119220);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
    "CVE-2017-10078",
    "CVE-2017-10081",
    "CVE-2017-10087",
    "CVE-2017-10089",
    "CVE-2017-10090",
    "CVE-2017-10096",
    "CVE-2017-10101",
    "CVE-2017-10102",
    "CVE-2017-10107",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10110",
    "CVE-2017-10111",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10135",
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );

  script_name(english:"Virtuozzo 6 : java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc (VZLSA-2017-1789)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the DCG implementation in the RMI component
of OpenJDK failed to correctly handle references. A remote attacker
could possibly use this flaw to execute arbitrary code with the
privileges of RMI registry or a Java RMI application. (CVE-2017-10102)

* Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries,
AWT, Hotspot, and Security components in OpenJDK. An untrusted Java
application or applet could use these flaws to completely bypass Java
sandbox restrictions. (CVE-2017-10107, CVE-2017-10096, CVE-2017-10101,
CVE-2017-10089, CVE-2017-10090, CVE-2017-10087, CVE-2017-10111,
CVE-2017-10110, CVE-2017-10074, CVE-2017-10067)

* It was discovered that the LDAPCertStore class in the Security
component of OpenJDK followed LDAP referrals to arbitrary URLs. A
specially crafted LDAP referral URL could cause LDAPCertStore to
communicate with non-LDAP servers. (CVE-2017-10116)

* It was discovered that the Nashorn JavaScript engine in the
Scripting component of OpenJDK could allow scripts to access Java APIs
even when access to Java APIs was disabled. An untrusted JavaScript
executed by Nashorn could use this flaw to bypass intended
restrictions. (CVE-2017-10078)

* It was discovered that the Security component of OpenJDK could fail
to properly enforce restrictions defined for processing of X.509
certificate chains. A remote attacker could possibly use this flaw to
make Java accept certificate using one of the disabled algorithms.
(CVE-2017-10198)

* A covert timing channel flaw was found in the DSA implementation in
the JCE component of OpenJDK. A remote attacker able to make a Java
application generate DSA signatures on demand could possibly use this
flaw to extract certain information about the used key via a timing
side channel. (CVE-2017-10115)

* A covert timing channel flaw was found in the PKCS#8 implementation
in the JCE component of OpenJDK. A remote attacker able to make a Java
application repeatedly compare PKCS#8 key against an attacker
controlled value could possibly use this flaw to determine the key via
a timing side channel. (CVE-2017-10135)

* It was discovered that the BasicAttribute and CodeSource classes in
OpenJDK did not limit the amount of memory allocated when creating
object instances from a serialized form. A specially crafted
serialized input stream could cause Java to consume an excessive
amount of memory. (CVE-2017-10108, CVE-2017-10109)

* Multiple flaws were found in the Hotspot and Security components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2017-10081,
CVE-2017-10193)

* It was discovered that the JPEGImageReader implementation in the 2D
component of OpenJDK would, in certain cases, read all image data even
if it was not used later. A specially crafted image could cause a Java
application to temporarily use an excessive amount of CPU and memory.
(CVE-2017-10053)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1789.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffc7c635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:1789");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-debug-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-demo-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-demo-debug-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-devel-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-devel-debug-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-headless-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-headless-debug-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-javadoc-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-javadoc-debug-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-src-1.8.0.141-2.b16.vl6",
        "java-1.8.0-openjdk-src-debug-1.8.0.141-2.b16.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc");
}
