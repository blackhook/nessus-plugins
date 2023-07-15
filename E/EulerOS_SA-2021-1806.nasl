#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149158);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2019-2762",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2842"
  );

  script_name(english:"EulerOS 2.0 SP3 : java-1.8.0-openjdk (EulerOS-SA-2021-1806)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Vulnerability in the Java SE, Java SE Embedded
    component of Oracle Java SE (subcomponent: Utilities).
    Supported versions that are affected are Java SE:
    7u221, 8u212, 11.0.3 and 12.0.1 Java SE Embedded:
    8u211. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2019-2762)

  - Vulnerability in the Java SE, Java SE Embedded
    component of Oracle Java SE (subcomponent: Utilities).
    Supported versions that are affected are Java SE:
    7u221, 8u212, 11.0.3 and 12.0.1 Java SE Embedded:
    8u211. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java SE, Java SE
    Embedded.(CVE-2019-2769)

  - Vulnerability in the Java SE component of Oracle Java
    SE (subcomponent: JCE). The supported version that is
    affected is Java SE: 8u212. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    Java SE. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial
    denial of service (partial DOS) of Java
    SE.(CVE-2019-2842)

  - Vulnerability in the Java SE, Java SE Embedded
    component of Oracle Java SE (subcomponent: Security).
    Supported versions that are affected are Java SE:
    8u212, 11.0.3 and 12.0.1 Java SE Embedded: 8u211.
    Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE
    Embedded. Successful attacks require human interaction
    from a person other than the attacker and while the
    vulnerability is in Java SE, Java SE Embedded, attacks
    may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Java SE, Java
    SE Embedded accessible data.(CVE-2019-2786)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1806
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe0123cf");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2786");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.191.b12-0.h14",
        "java-1.8.0-openjdk-devel-1.8.0.191.b12-0.h14",
        "java-1.8.0-openjdk-headless-1.8.0.191.b12-0.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
