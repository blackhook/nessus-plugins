#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139159);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-11996",
    "CVE-2020-13934",
    "CVE-2020-13935",
    "CVE-2020-9484"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP8 : tomcat (EulerOS-SA-2020-1829)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The payload length in a WebSocket frame was not
    correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and
    7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with
    invalid payload lengths could lead to a denial of
    service.(CVE-2020-13935)

  - An h2c direct connection to Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56 did
    not release the HTTP/1.1 processor after the upgrade to
    HTTP/2. If a sufficient number of such requests were
    made, an OutOfMemoryException could occur leading to a
    denial of service.(CVE-2020-13934)

  - A specially crafted sequence of HTTP/2 requests sent to
    Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to
    9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage
    for several seconds. If a sufficient number of such
    requests were made on concurrent HTTP/2 connections,
    the server could become unresponsive.(CVE-2020-11996)

  - When using Apache Tomcat versions 10.0.0-M1 to
    10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and
    7.0.0 to 7.0.103 if a) an attacker is able to control
    the contents and name of a file on the server and b)
    the server is configured to use the PersistenceManager
    with a FileStore and c) the PersistenceManager is
    configured with
    sessionAttributeValueClassNameFilter='null' (the
    default unless a SecurityManager is used) or a
    sufficiently lax filter to allow the attacker provided
    object to be deserialized and d) the attacker knows the
    relative file path from the storage location used by
    FileStore to the file the attacker has control over
    then, using a specifically crafted request, the
    attacker will be able to trigger remote code execution
    via deserialization of the file under their control.
    Note that all of conditions a) to d) must be true for
    the attack to succeed.(CVE-2020-9484)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1829
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?542740fa");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-el-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-servlet-4.0-api");
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

pkgs = ["tomcat-9.0.10-1.h9.eulerosv2r8",
        "tomcat-admin-webapps-9.0.10-1.h9.eulerosv2r8",
        "tomcat-el-3.0-api-9.0.10-1.h9.eulerosv2r8",
        "tomcat-jsp-2.3-api-9.0.10-1.h9.eulerosv2r8",
        "tomcat-lib-9.0.10-1.h9.eulerosv2r8",
        "tomcat-servlet-4.0-api-9.0.10-1.h9.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
