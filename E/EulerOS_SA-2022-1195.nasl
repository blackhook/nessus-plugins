#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/23");

  script_cve_id(
    "CVE-2021-35556",
    "CVE-2021-35559",
    "CVE-2021-35561",
    "CVE-2021-35564",
    "CVE-2021-35565",
    "CVE-2021-35586"
  );
  script_xref(name:"IAVA", value:"2021-A-0481-S");

  script_name(english:"EulerOS 2.0 SP8 : java-1.8.0-openjdk (EulerOS-SA-2022-1195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35556)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Swing). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35559)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Utility). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35561)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Keytool). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N). (CVE-2021-35564)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    JSSE). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12; Oracle GraalVM Enterprise
    Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via TLS to compromise Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying
    data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted
    Java applets, such as through a web service. CVSS 3.1 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35565)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    ImageIO). Supported versions that are affected are Java SE: 7u311, 8u301, 11.0.12, 17; Oracle GraalVM
    Enterprise Edition: 20.3.3 and 21.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability can also be exploited by using APIs in the specified Component,
    e.g., through a web service which supplies data to the APIs. CVSS 3.1 Base Score 5.3 (Availability
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2021-35586)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1195
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f8682dc");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "java-1.8.0-openjdk-1.8.0.181.b15-5.h24.eulerosv2r8",
  "java-1.8.0-openjdk-devel-1.8.0.181.b15-5.h24.eulerosv2r8",
  "java-1.8.0-openjdk-headless-1.8.0.181.b15-5.h24.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
