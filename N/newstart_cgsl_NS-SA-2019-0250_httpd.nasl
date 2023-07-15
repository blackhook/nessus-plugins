#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0250. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132454);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-0217", "CVE-2019-0220");
  script_bugtraq_id(107668, 107670);
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : httpd Multiple Vulnerabilities (NS-SA-2019-0250)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has httpd packages installed that are affected by
multiple vulnerabilities:

  - A vulnerability was found in Apache HTTP Server 2.4.0 to
    2.4.38. When the path component of a request URL
    contains multiple consecutive slashes ('/'), directives
    such as LocationMatch and RewriteRule must account for
    duplicates in regular expressions while other aspects of
    the servers processing will implicitly collapse them.
    (CVE-2019-0220)

  - In Apache HTTP Server 2.4 release 2.4.38 and prior, a
    race condition in mod_auth_digest when running in a
    threaded server could allow a user with valid
    credentials to authenticate using another username,
    bypassing configured access control restrictions.
    (CVE-2019-0217)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0250");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL httpd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "httpd-2.4.6-90.el7.centos",
    "httpd-debuginfo-2.4.6-90.el7.centos",
    "httpd-devel-2.4.6-90.el7.centos",
    "httpd-manual-2.4.6-90.el7.centos",
    "httpd-tools-2.4.6-90.el7.centos",
    "mod_ldap-2.4.6-90.el7.centos",
    "mod_proxy_html-2.4.6-90.el7.centos",
    "mod_session-2.4.6-90.el7.centos",
    "mod_ssl-2.4.6-90.el7.centos"
  ],
  "CGSL MAIN 5.05": [
    "httpd-2.4.6-90.el7.centos",
    "httpd-debuginfo-2.4.6-90.el7.centos",
    "httpd-devel-2.4.6-90.el7.centos",
    "httpd-manual-2.4.6-90.el7.centos",
    "httpd-tools-2.4.6-90.el7.centos",
    "mod_ldap-2.4.6-90.el7.centos",
    "mod_proxy_html-2.4.6-90.el7.centos",
    "mod_session-2.4.6-90.el7.centos",
    "mod_ssl-2.4.6-90.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
