#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0130 and 
# Oracle Linux Security Advisory ELSA-2013-0130 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68701);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0455", "CVE-2008-0456", "CVE-2012-2687");
  script_bugtraq_id(27409, 55131);
  script_xref(name:"RHSA", value:"2013:0130");

  script_name(english:"Oracle Linux 5 : httpd (ELSA-2013-0130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0130 :

Updated httpd packages that fix multiple security issues, various
bugs, and add enhancements are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The httpd packages contain the Apache HTTP Server (httpd), which is
the namesake project of The Apache Software Foundation.

Input sanitization flaws were found in the mod_negotiation module. A
remote attacker able to upload or create files with arbitrary names in
a directory that has the MultiViews options enabled, could use these
flaws to conduct cross-site scripting and HTTP response splitting
attacks against users visiting the site. (CVE-2008-0455,
CVE-2008-0456, CVE-2012-2687)

Bug fixes :

* Previously, no check was made to see if the
/etc/pki/tls/private/localhost.key file was a valid key prior to
running the '%post' script for the 'mod_ssl' package. Consequently,
when /etc/pki/tls/certs/localhost.crt did not exist and
'localhost.key' was present but invalid, upgrading the Apache HTTP
Server daemon (httpd) with mod_ssl failed. The '%post' script has been
fixed to test for an existing SSL key. As a result, upgrading httpd
with mod_ssl now proceeds as expected. (BZ#752618)

* The 'mod_ssl' module did not support operation under FIPS mode.
Consequently, when operating Red Hat Enterprise Linux 5 with FIPS mode
enabled, httpd failed to start. An upstream patch has been applied to
disable non-FIPS functionality if operating under FIPS mode and httpd
now starts as expected. (BZ#773473)

* Prior to this update, httpd exit status codes were not Linux
Standard Base (LSB) compliant. When the command 'service httpd reload'
was run and httpd failed, the exit status code returned was '0' and
not in the range 1 to 6 as expected. A patch has been applied to the
init script and httpd now returns '1' as an exit status code.
(BZ#783242)

* Chunked Transfer Coding is described in RFC 2616. Previously, the
Apache server did not correctly handle a chunked encoded POST request
with a 'chunk-size' or 'chunk-extension' value of 32 bytes or more.
Consequently, when such a POST request was made the server did not
respond. An upstream patch has been applied and the problem no longer
occurs. (BZ#840845)

* Due to a regression, when mod_cache received a non-cacheable 304
response, the headers were served incorrectly. Consequently,
compressed data could be returned to the client without the cached
headers to indicate the data was compressed. An upstream patch has
been applied to merge response and cached headers before data from the
cache is served to the client. As a result, cached data is now
correctly interpreted by the client. (BZ#845532)

* In a proxy configuration, certain response-line strings were not
handled correctly. If a response-line without a 'description' string
was received from the origin server, for a non-standard status code,
such as the '450' status code, a '500 Internal Server Error' would be
returned to the client. This bug has been fixed so that the original
response line is returned to the client. (BZ#853128)

Enhancements :

* The configuration directive 'LDAPReferrals' is now supported in
addition to the previously introduced 'LDAPChaseReferrals'.
(BZ#727342)

* The AJP support module for 'mod_proxy', 'mod_proxy_ajp', now
supports the 'ProxyErrorOverride' directive. Consequently, it is now
possible to configure customized error pages for web applications
running on a backend server accessed via AJP. (BZ#767890)

* The '%posttrans' scriptlet which automatically restarts the httpd
service after a package upgrade can now be disabled. If the file
/etc/sysconfig/httpd-disable-posttrans exists, the scriptlet will not
restart the daemon. (BZ#833042)

* The output of 'httpd -S' now includes configured alias names for
each virtual host. (BZ#833043)

* New certificate variable names are now exposed by 'mod_ssl' using
the '_DN_userID' suffix, such as 'SSL_CLIENT_S_DN_userID', which use
the commonly used object identifier (OID) definition of 'userID', OID
0.9.2342.19200300.100.1.1. (BZ#840036)

All users of httpd are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003201.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"httpd-2.2.3-74.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-devel-2.2.3-74.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-manual-2.2.3-74.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mod_ssl-2.2.3-74.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
}
