#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101412);
  script_version("1.62");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5552",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3261",
    "CVE-2017-3272",
    "CVE-2017-3289"
  );

  script_name(english:"Virtuozzo 6 : java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc (VZLSA-2017-0180)");
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
website.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-0180.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f2e18b6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-0180");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

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

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["java-1.8.0-openjdk-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-debug-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-demo-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-demo-debug-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-devel-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-devel-debug-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-headless-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-headless-debug-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-javadoc-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-javadoc-debug-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-src-1.8.0.121-0.b13.vl6",
        "java-1.8.0-openjdk-src-debug-1.8.0.121-0.b13.vl6"];

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
