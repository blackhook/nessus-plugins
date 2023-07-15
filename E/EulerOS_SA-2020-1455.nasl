#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135617);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-8109",
    "CVE-2018-1283",
    "CVE-2018-1301",
    "CVE-2019-0220",
    "CVE-2019-10092",
    "CVE-2019-10098"
  );
  script_bugtraq_id(73040);
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : httpd (EulerOS-SA-2020-1455)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was found in Apache HTTP Server 2.4.0
    to 2.4.38. When the path component of a request URL
    contains multiple consecutive slashes ('/'), directives
    such as LocationMatch and RewriteRule must account for
    duplicates in regular expressions while other aspects
    of the servers processing will implicitly collapse
    them.(CVE-2019-0220)

  - A specially crafted request could have crashed the
    Apache HTTP Server prior to version 2.4.30, due to an
    out of bound access after a size limit is reached by
    reading the HTTP header. This vulnerability is
    considered very hard if not impossible to trigger in
    non-debug mode (both log and build level), so it is
    classified as low risk for common server
    usage.(CVE-2018-1301)

  - In Apache httpd 2.4.0 to 2.4.29, when mod_session is
    configured to forward its session data to CGI
    applications (SessionEnv on, not the default), a remote
    user may influence their content by using a 'Session'
    header. This comes from the 'HTTP_SESSION' variable
    name used by mod_session to forward its data to CGIs,
    since the prefix 'HTTP_' is also used by the Apache
    HTTP Server to pass HTTP header fields, per CGI
    specifications.(CVE-2018-1283)

  - mod_lua.c in the mod_lua module in the Apache HTTP
    Server 2.3.x and 2.4.x through 2.4.10 does not support
    an httpd configuration in which the same Lua
    authorization provider is used with different arguments
    within different contexts, which allows remote
    attackers to bypass intended access restrictions in
    opportunistic circumstances by leveraging multiple
    Require directives, as demonstrated by a configuration
    that specifies authorization for one group to access a
    certain directory, and authorization for a second group
    to access a second directory.(CVE-2014-8109)

  - In Apache HTTP server 2.4.0 to 2.4.39, Redirects
    configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines
    and redirect instead to an unexpected URL within the
    request URL.(CVE-2019-10098)

  - In Apache HTTP Server 2.4.0-2.4.39, a limited
    cross-site scripting issue was reported affecting the
    mod_proxy error page. An attacker could cause the link
    on the error page to be malformed and instead point to
    a page of their choice. This would only be exploitable
    where a server was set up with proxying enabled but was
    misconfigured in such a way that the Proxy Error page
    was displayed.(CVE-2019-10092)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1455
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83875bfe");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["httpd-2.4.6-80.1.h8.eulerosv2r7",
        "httpd-tools-2.4.6-80.1.h8.eulerosv2r7",
        "mod_ssl-2.4.6-80.1.h8.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
