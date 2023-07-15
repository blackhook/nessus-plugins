#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99872);
  script_version("1.53");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

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

  script_name(english:"EulerOS 2.0 SP1 : java-1.7.0-openjdk (EulerOS-SA-2017-1027)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.7.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered that the RMI registry and DCG
    implementations in the RMI component of OpenJDK
    performed deserialization of untrusted inputs. A remote
    attacker could possibly use this flaw to execute
    arbitrary code with the privileges of RMI registry or a
    Java RMI application. (CVE-2017-3241)

  - Multiple flaws were discovered in the Libraries and
    Hotspot components in OpenJDK. An untrusted Java
    application or applet could use these flaws to
    completely bypass Java sandbox restrictions.
    (CVE-2017-3272, CVE-2017-3289)

  - A covert timing channel flaw was found in the DSA
    implementation in the Libraries component of OpenJDK. A
    remote attacker could possibly use this flaw to extract
    certain information about the used key via a timing
    side channel. (CVE-2016-5548)

  - It was discovered that the Libraries component of
    OpenJDK accepted ECSDA signatures using non-canonical
    DER encoding. This could cause a Java application to
    accept signature in an incorrect format not accepted by
    other cryptographic tools. (CVE-2016-5546)

  - It was discovered that the 2D component of OpenJDK
    performed parsing of iTXt and zTXt PNG image chunks
    even when configured to ignore metadata. An attacker
    able to make a Java application parse a specially
    crafted PNG image could cause the application to
    consume an excessive amount of memory. (CVE-2017-3253)

  - It was discovered that the Libraries component of
    OpenJDK did not validate the length of the object
    identifier read from the DER input before allocating
    memory to store the OID. An attacker able to make a
    Java application decode a specially crafted DER input
    could cause the application to consume an excessive
    amount of memory. (CVE-2016-5547)

  - It was discovered that the JAAS component of OpenJDK
    did not use the correct way to extract user DN from the
    result of the user search LDAP query. A specially
    crafted user LDAP entry could cause the application to
    use an incorrect DN. (CVE-2017-3252)

  - It was discovered that the Networking component of
    OpenJDK failed to properly parse user info from the
    URL. A remote attacker could cause a Java application
    to incorrectly parse an attacker supplied URL and
    interpret it differently from other applications
    processing the same URL. (CVE-2016-5552)

  - Multiple flaws were found in the Networking components
    in OpenJDK. An untrusted Java application or applet
    could use these flaws to bypass certain Java sandbox
    restrictions. (CVE-2017-3261, CVE-2017-3231)

  - A flaw was found in the way the DES/3DES cipher was
    used as part of the TLS/SSL protocol. A
    man-in-the-middle attacker could use this flaw to
    recover some plaintext data by capturing large amounts
    of encrypted traffic between TLS/SSL server and client
    if the communication used a DES/3DES based ciphersuite.
    (CVE-2016-2183)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1027
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5d55422");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.7.0-openjdk-1.7.0.131-2.6.9.0",
        "java-1.7.0-openjdk-devel-1.7.0.131-2.6.9.0",
        "java-1.7.0-openjdk-headless-1.7.0.131-2.6.9.0"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
