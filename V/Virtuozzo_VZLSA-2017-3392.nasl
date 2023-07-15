#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105086);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-10193",
    "CVE-2017-10198",
    "CVE-2017-10274",
    "CVE-2017-10281",
    "CVE-2017-10285",
    "CVE-2017-10295",
    "CVE-2017-10345",
    "CVE-2017-10346",
    "CVE-2017-10347",
    "CVE-2017-10348",
    "CVE-2017-10349",
    "CVE-2017-10350",
    "CVE-2017-10355",
    "CVE-2017-10356",
    "CVE-2017-10357",
    "CVE-2017-10388"
  );

  script_name(english:"Virtuozzo 7 : java-1.7.0-openjdk / etc (VZLSA-2017-3392)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* Multiple flaws were discovered in the RMI and Hotspot components in
OpenJDK. An untrusted Java application or applet could use these flaws
to completely bypass Java sandbox restrictions. (CVE-2017-10285,
CVE-2017-10346)

* It was discovered that the Kerberos client implementation in the
Libraries component of OpenJDK used the sname field from the plain
text part rather than encrypted part of the KDC reply message. A
man-in-the-middle attacker could possibly use this flaw to impersonate
Kerberos services to Java applications acting as Kerberos clients.
(CVE-2017-10388)

* It was discovered that the Security component of OpenJDK generated
weak password-based encryption keys used to protect private keys
stored in key stores. This made it easier to perform password guessing
attacks to decrypt stored keys if an attacker could gain access to a
key store. (CVE-2017-10356)

* Multiple flaws were found in the Smart Card IO and Security
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2017-10274, CVE-2017-10193)

* It was found that the FtpClient implementation in the Networking
component of OpenJDK did not set connect and read timeouts by default.
A malicious FTP server or a man-in-the-middle attacker could use this
flaw to block execution of a Java application connecting to an FTP
server. (CVE-2017-10355)

* It was found that the HttpURLConnection and HttpsURLConnection
classes in the Networking component of OpenJDK failed to check for
newline characters embedded in URLs. An attacker able to make a Java
application perform an HTTP request using an attacker provided URL
could possibly inject additional headers into the request.
(CVE-2017-10295)

* It was discovered that the Security component of OpenJDK could fail
to properly enforce restrictions defined for processing of X.509
certificate chains. A remote attacker could possibly use this flaw to
make Java accept certificate using one of the disabled algorithms.
(CVE-2017-10198)

* It was discovered that multiple classes in the JAXP, Serialization,
Libraries, and JAX-WS components of OpenJDK did not limit the amount
of memory allocated when creating object instances from the serialized
form. A specially crafted input could cause a Java application to use
an excessive amount of memory when deserialized. (CVE-2017-10349,
CVE-2017-10357, CVE-2017-10347, CVE-2017-10281, CVE-2017-10345,
CVE-2017-10348, CVE-2017-10350)

Bug Fix(es) :

* Previously, OpenJDK could not handle situations when the kernel
blocked on a read even when polling the socket indicated that a read
is possible. As a consequence, OpenJDK could hang indefinitely. With
this update, OpenJDK polls with a timeout and performs a non-blocking
read on success, and it no longer hangs in these situations.
(BZ#1508357)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-3392.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca5e4d09");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3392");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["java-1.7.0-openjdk-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-accessibility-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-demo-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-devel-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-headless-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-javadoc-1.7.0.161-2.6.12.0.vl7",
        "java-1.7.0-openjdk-src-1.7.0.161-2.6.12.0.vl7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / etc");
}
