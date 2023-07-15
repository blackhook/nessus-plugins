#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136859);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659",
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2773",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2830"
  );

  script_name(english:"EulerOS 2.0 SP8 : java-1.8.0-openjdk (EulerOS-SA-2020-1581)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1 Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Java SE,
    Java SE Embedded. While the vulnerability is in Java
    SE, Java SE Embedded, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE, Java
    SE Embedded accessible data.(CVE-2020-2601)

  - Vulnerability in the Java SE product of Oracle Java SE
    (component: Libraries). Supported versions that are
    affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE.(CVE-2020-2654)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u241 and 8u231
    Java SE Embedded: 8u231. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded.(CVE-2020-2659)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Networking). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1 Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of
    Java SE, Java SE Embedded accessible data as well as
    unauthorized read access to a subset of Java SE, Java
    SE Embedded accessible data.(CVE-2020-2593)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1 Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Java SE,
    Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Java SE, Java SE Embedded
    accessible data.(CVE-2020-2590)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1 Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded.
    (CVE-2020-2583)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: JSSE). Supported versions
    that are affected are Java SE: 7u251, 8u241, 11.0.6 and
    14 Java SE Embedded: 8u241. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via HTTPS to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2781)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Lightweight HTTP Server).
    Supported versions that are affected are Java SE:
    7u251, 8u241, 11.0.6 and 14 Java SE Embedded: 8u241.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Java SE, Java SE Embedded accessible data as
    well as unauthorized read access to a subset of Java
    SE, Java SE Embedded accessible data.(CVE-2020-2800)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Concurrency). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2830)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u241, 11.0.6
    and 14 Java SE Embedded: 8u241. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded.(CVE-2020-2754)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u241, 11.0.6
    and 14 Java SE Embedded: 8u241. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java
    SE, Java SE Embedded.(CVE-2020-2755)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded.
    (CVE-2020-2756)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE Embedded.
    .(CVE-2020-2757)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u251, 8u241,
    11.0.6 and 14 Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2020-2773)

  - A flaw was found in the boundary checks in the java.nio
    buffer classes in the Libraries component of OpenJDK,
    where it is bypassed in certain cases. This flaw allows
    an untrusted Java application or applet o bypass Java
    sandbox restrictions.(CVE-2020-2803)

  - A flaw was found in the way the readObject() method of
    the MethodType class in the Libraries component of
    OpenJDK checked argument types. This flaw allows an
    untrusted Java application or applet to bypass Java
    sandbox restrictions.(CVE-2020-2805)

  - Vulnerability in the Java SE, Java SE Embedded product
    of Oracle Java SE (component: Serialization). Supported
    versions that are affected are Java SE: 7u241, 8u231,
    11.0.5 and 13.0.1 Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful
    attacks of this vulnerability can result in takeover of
    Java SE, Java SE Embedded.(CVE-2020-2604)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1581
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?711cf805");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.181.b15-5.h12.eulerosv2r8",
        "java-1.8.0-openjdk-devel-1.8.0.181.b15-5.h12.eulerosv2r8",
        "java-1.8.0-openjdk-headless-1.8.0.181.b15-5.h12.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
