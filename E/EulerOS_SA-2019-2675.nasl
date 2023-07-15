#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132210);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-1304",
    "CVE-2018-1305",
    "CVE-2018-8034"
  );

  script_name(english:"EulerOS 2.0 SP3 : tomcat (EulerOS-SA-2019-2675)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tomcat packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Security constraints defined by annotations of Servlets
    in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27,
    8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 were only
    applied once a Servlet had been loaded. Because
    security constraints defined in this way apply to the
    URL pattern and any URLs below that point, it was
    possible - depending on the order Servlets were loaded
    - for some security constraints not to be applied. This
    could have exposed resources to users who were not
    authorised to access them.(CVE-2018-1305)

  - The host name verification when using TLS with the
    WebSocket client was missing. It is now enabled by
    default. Versions Affected: Apache Tomcat 9.0.0.M1 to
    9.0.9, 8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52, and 7.0.35
    to 7.0.88.(CVE-2018-8034)

  - The URL pattern of '' (the empty string) which exactly
    maps to the context root was not correctly handled in
    Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27,
    8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when used as
    part of a security constraint definition. This caused
    the constraint to be ignored. It was, therefore,
    possible for unauthorised users to gain access to web
    application resources that should have been protected.
    Only security constraints with a URL pattern of the
    empty string were affected.(CVE-2018-1304)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2675
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4a9295d");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["tomcat-7.0.76-8.h6",
        "tomcat-admin-webapps-7.0.76-8.h6",
        "tomcat-el-2.2-api-7.0.76-8.h6",
        "tomcat-jsp-2.2-api-7.0.76-8.h6",
        "tomcat-lib-7.0.76-8.h6",
        "tomcat-servlet-3.0-api-7.0.76-8.h6",
        "tomcat-webapps-7.0.76-8.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
