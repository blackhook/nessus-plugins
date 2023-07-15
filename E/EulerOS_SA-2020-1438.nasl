#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135567);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2019-12418", "CVE-2019-17563", "CVE-2020-1938");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"EulerOS 2.0 SP3 : tomcat (EulerOS-SA-2020-1438)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - When using the Apache JServ Protocol (AJP), care must
    be taken when trusting incoming connections to Apache
    Tomcat. Tomcat treats AJP connections as having higher
    trust than, for example, a similar HTTP connection. If
    such connections are available to an attacker, they can
    be exploited in ways that may be surprising. In Apache
    Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0
    to 7.0.99, Tomcat shipped with an AJP Connector enabled
    by default that listened on all configured IP
    addresses. It was expected (and recommended in the
    security guide) that this Connector would be disabled
    if not required. This vulnerability report identified a
    mechanism that allowed: - returning arbitrary files
    from anywhere in the web application - processing any
    file in the web application as a JSP Further, if the
    web application allowed file upload and stored those
    files within the web application (or the attacker was
    able to control the content of the web application by
    some other means) then this, along with the ability to
    process a file as a JSP, made remote code execution
    possible. It is important to note that mitigation is
    only required if an AJP port is accessible to untrusted
    users. Users wishing to take a defence-in-depth
    approach and block the vector that permits returning
    arbitrary files and execution as JSP may upgrade to
    Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A
    number of changes were made to the default AJP
    Connector configuration in 9.0.31 to harden the default
    configuration. It is likely that users upgrading to
    9.0.31, 8.5.51 or 7.0.100 or later will need to make
    small changes to their configurations.(CVE-2020-1938)

  - When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47,
    7.0.0 and 7.0.97 is configured with the JMX Remote
    Lifecycle Listener, a local attacker without access to
    the Tomcat process or configuration files is able to
    manipulate the RMI registry to perform a
    man-in-the-middle attack to capture user names and
    passwords used to access the JMX interface. The
    attacker can then use these credentials to access the
    JMX interface and gain complete control over the Tomcat
    instance.(CVE-2019-12418)

  - When using FORM authentication with Apache Tomcat
    9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98
    there was a narrow window where an attacker could
    perform a session fixation attack. The window was
    considered too narrow for an exploit to be practical
    but, erring on the side of caution, this issue has been
    treated as a security vulnerability.(CVE-2019-17563)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1438
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59d11dcf");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["tomcat-7.0.76-8.h8",
        "tomcat-admin-webapps-7.0.76-8.h8",
        "tomcat-el-2.2-api-7.0.76-8.h8",
        "tomcat-jsp-2.2-api-7.0.76-8.h8",
        "tomcat-lib-7.0.76-8.h8",
        "tomcat-servlet-3.0-api-7.0.76-8.h8",
        "tomcat-webapps-7.0.76-8.h8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
