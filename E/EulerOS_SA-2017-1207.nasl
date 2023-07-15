#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103065);
  script_version("3.36");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-10053",
    "CVE-2017-10067",
    "CVE-2017-10074",
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
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10135",
    "CVE-2017-10243"
  );

  script_name(english:"EulerOS 2.0 SP1 : java-1.7.0-openjdk (EulerOS-SA-2017-1207)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.7.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered that the DCG implementation in the
    RMI component of OpenJDK failed to correctly handle
    references. A remote attacker could possibly use this
    flaw to execute arbitrary code with the privileges of
    RMI registry or a Java RMI application.
    (CVE-2017-10102)

  - Multiple flaws were discovered in the RMI, JAXP,
    ImageIO, Libraries, AWT, Hotspot, and Security
    components in OpenJDK. An untrusted Java application or
    applet could use these flaws to completely bypass Java
    sandbox restrictions. (CVE-2017-10107, CVE-2017-10096,
    CVE-2017-10101, CVE-2017-10089, CVE-2017-10090,
    CVE-2017-10087, CVE-2017-10110, CVE-2017-10074,
    CVE-2017-10067)

  - It was discovered that the LDAPCertStore class in the
    Security component of OpenJDK followed LDAP referrals
    to arbitrary URLs. A specially crafted LDAP referral
    URL could cause LDAPCertStore to communicate with
    non-LDAP servers. (CVE-2017-10116)

  - It was discovered that the wsdlimport tool in the
    JAX-WS component of OpenJDK did not use secure XML
    parser settings when parsing WSDL XML documents. A
    specially crafted WSDL document could cause wsdlimport
    to use an excessive amount of CPU and memory, open
    connections to other hosts, or leak information.
    (CVE-2017-10243)

  - A covert timing channel flaw was found in the DSA
    implementation in the JCE component of OpenJDK. A
    remote attacker able to make a Java application
    generate DSA signatures on demand could possibly use
    this flaw to extract certain information about the used
    key via a timing side channel. (CVE-2017-10115)

  - A covert timing channel flaw was found in the PKCS#8
    implementation in the JCE component of OpenJDK. A
    remote attacker able to make a Java application
    repeatedly compare PKCS#8 key against an attacker
    controlled value could possibly use this flaw to
    determine the key via a timing side channel.
    (CVE-2017-10135)

  - It was discovered that the BasicAttribute and
    CodeSource classes in OpenJDK did not limit the amount
    of memory allocated when creating object instances from
    a serialized form. A specially crafted serialized input
    stream could cause Java to consume an excessive amount
    of memory. (CVE-2017-10108, CVE-2017-10109)

  - A flaw was found in the Hotspot component in OpenJDK.
    An untrusted Java application or applet could use this
    flaw to bypass certain Java sandbox restrictions.
    (CVE-2017-10081)

  - It was discovered that the JPEGImageReader
    implementation in the 2D component of OpenJDK would, in
    certain cases, read all image data even if it was not
    used later. A specially crafted image could cause a
    Java application to temporarily use an excessive amount
    of CPU and memory. (CVE-2017-10053)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1207
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?247aa357");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");

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

pkgs = ["java-1.7.0-openjdk-1.7.0.151-2.6.11.1",
        "java-1.7.0-openjdk-devel-1.7.0.151-2.6.11.1",
        "java-1.7.0-openjdk-headless-1.7.0.151-2.6.11.1"];

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
