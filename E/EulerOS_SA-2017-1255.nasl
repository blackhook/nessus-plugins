#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104280);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
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

  script_name(english:"EulerOS 2.0 SP2 : java-1.8.0-openjdk (EulerOS-SA-2017-1255)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Multiple flaws were discovered in the RMI and Hotspot
    components in OpenJDK. An untrusted Java application or
    applet could use these flaws to completely bypass Java
    sandbox restrictions. (CVE-2017-10285, CVE-2017-10346)

  - It was discovered that the Kerberos client
    implementation in the Libraries component of OpenJDK
    used the sname field from the plain text part rather
    than encrypted part of the KDC reply message. A
    man-in-the-middle attacker could possibly use this flaw
    to impersonate Kerberos services to Java applications
    acting as Kerberos clients. (CVE-2017-10388)

  - It was discovered that the Security component of
    OpenJDK generated weak password-based encryption keys
    used to protect private keys stored in key stores. This
    made it easier to perform password guessing attacks to
    decrypt stored keys if an attacker could gain access to
    a key store. (CVE-2017-10356)

  - A flaw was found in the Smart Card IO component in
    OpenJDK. An untrusted Java application or applet could
    use this flaw to bypass certain Java sandbox
    restrictions. (CVE-2017-10274)

  - It was found that the FtpClient implementation in the
    Networking component of OpenJDK did not set connect and
    read timeouts by default. A malicious FTP server or a
    man-in-the-middle attacker could use this flaw to block
    execution of a Java application connecting to an FTP
    server. (CVE-2017-10355)

  - It was found that the HttpURLConnection and
    HttpsURLConnection classes in the Networking component
    of OpenJDK failed to check for newline characters
    embedded in URLs. An attacker able to make a Java
    application perform an HTTP request using an attacker
    provided URL could possibly inject additional headers
    into the request. (CVE-2017-10295)

  - It was discovered that multiple classes in the JAXP,
    Serialization, Libraries, and JAX-WS components of
    OpenJDK did not limit the amount of memory allocated
    when creating object instances from the serialized
    form. A specially-crafted input could cause a Java
    application to use an excessive amount of memory when
    deserialized. (CVE-2017-10349, CVE-2017-10357,
    CVE-2017-10347, CVE-2017-10281, CVE-2017-10345,
    CVE-2017-10348, CVE-2017-10350)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1255
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dea628c6");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.151-1.b12",
        "java-1.8.0-openjdk-devel-1.8.0.151-1.b12",
        "java-1.8.0-openjdk-headless-1.8.0.151-1.b12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
