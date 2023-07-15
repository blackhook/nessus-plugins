#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101462);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );

  script_name(english:"Virtuozzo 6 : java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc (VZLSA-2017-1204)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* An untrusted library search path flaw was found in the JCE component
of OpenJDK. A local attacker could possibly use this flaw to cause a
Java application using JCE to load an attacker-controlled library and
hence escalate their privileges. (CVE-2017-3511)

* It was found that the JAXP component of OpenJDK failed to correctly
enforce parse tree size limits when parsing XML document. An attacker
able to make a Java application parse a specially crafted XML document
could use this flaw to make it consume an excessive amount of CPU and
memory. (CVE-2017-3526)

* It was discovered that the HTTP client implementation in the
Networking component of OpenJDK could cache and re-use an NTLM
authenticated connection in a different security context. A remote
attacker could possibly use this flaw to make a Java application
perform HTTP requests authenticated with credentials of a different
user. (CVE-2017-3509)

Note: This update adds support for the 'jdk.ntlm.cache' system
property which, when set to false, prevents caching of NTLM
connections and authentications and hence prevents this issue.
However, caching remains enabled by default.

* It was discovered that the Security component of OpenJDK did not
allow users to restrict the set of algorithms allowed for Jar
integrity verification. This flaw could allow an attacker to modify
content of the Jar file that used weak signing key or hash algorithm.
(CVE-2017-3539)

Note: This updates extends the fix for CVE-2016-5542 released as part
of the RHSA-2016:2658 erratum to no longer allow the MD5 hash
algorithm during the Jar integrity verification by adding it to the
jdk.jar.disabledAlgorithms security property.

* Newline injection flaws were discovered in FTP and SMTP client
implementations in the Networking component in OpenJDK. A remote
attacker could possibly use these flaws to manipulate FTP or SMTP
connections established by a Java application. (CVE-2017-3533,
CVE-2017-3544)

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1204.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7c37394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1204");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");
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

pkgs = ["java-1.7.0-openjdk-1.7.0.141-2.6.10.1.vl6",
        "java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.vl6",
        "java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.vl6",
        "java-1.7.0-openjdk-javadoc-1.7.0.141-2.6.10.1.vl6",
        "java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-demo / etc");
}
