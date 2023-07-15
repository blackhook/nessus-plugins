##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0055. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143961);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : tomcat Vulnerability (NS-SA-2020-0055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has tomcat packages installed that are affected by
a vulnerability:

  - When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to
    7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the
    server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is
    configured with sessionAttributeValueClassNameFilter=null (the default unless a SecurityManager is used)
    or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker
    knows the relative file path from the storage location used by FileStore to the file the attacker has
    control over; then, using a specifically crafted request, the attacker will be able to trigger remote code
    execution via deserialization of the file under their control. Note that all of conditions a) to d) must
    be true for the attack to succeed. (CVE-2020-9484)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0055");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tomcat packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'tomcat-7.0.76-12.el7_8',
    'tomcat-admin-webapps-7.0.76-12.el7_8',
    'tomcat-docs-webapp-7.0.76-12.el7_8',
    'tomcat-el-2.2-api-7.0.76-12.el7_8',
    'tomcat-javadoc-7.0.76-12.el7_8',
    'tomcat-jsp-2.2-api-7.0.76-12.el7_8',
    'tomcat-jsvc-7.0.76-12.el7_8',
    'tomcat-lib-7.0.76-12.el7_8',
    'tomcat-servlet-3.0-api-7.0.76-12.el7_8',
    'tomcat-webapps-7.0.76-12.el7_8'
  ],
  'CGSL MAIN 5.04': [
    'tomcat-7.0.76-12.el7_8',
    'tomcat-admin-webapps-7.0.76-12.el7_8',
    'tomcat-docs-webapp-7.0.76-12.el7_8',
    'tomcat-el-2.2-api-7.0.76-12.el7_8',
    'tomcat-javadoc-7.0.76-12.el7_8',
    'tomcat-jsp-2.2-api-7.0.76-12.el7_8',
    'tomcat-jsvc-7.0.76-12.el7_8',
    'tomcat-lib-7.0.76-12.el7_8',
    'tomcat-servlet-3.0-api-7.0.76-12.el7_8',
    'tomcat-webapps-7.0.76-12.el7_8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat');
}
