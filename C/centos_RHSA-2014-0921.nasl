#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0921 and 
# CentOS Errata and Security Advisory 2014:0921 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76716);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4352", "CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_xref(name:"RHSA", value:"2014:0921");

  script_name(english:"CentOS 7 : httpd (CESA-2014:0921)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

A race condition flaw, leading to heap-based buffer overflows, was
found in the mod_status httpd module. A remote attacker able to access
a status page served by mod_status on a server using a threaded
Multi-Processing Module (MPM) could send a specially crafted request
that would cause the httpd child process to crash or, possibly, allow
the attacker to execute arbitrary code with the privileges of the
'apache' user. (CVE-2014-0226)

A NULL pointer dereference flaw was found in the mod_cache httpd
module. A malicious HTTP server could cause the httpd child process to
crash when the Apache HTTP Server was used as a forward proxy with
caching. (CVE-2013-4352)

A denial of service flaw was found in the mod_proxy httpd module. A
remote attacker could send a specially crafted request to a server
configured as a reverse proxy using a threaded Multi-Processing
Modules (MPM) that would cause the httpd child process to crash.
(CVE-2014-0117)

A denial of service flaw was found in the way httpd's mod_deflate
module handled request body decompression (configured via the
'DEFLATE' input filter). A remote attacker able to send a request
whose body would be decompressed could use this flaw to consume an
excessive amount of system memory and CPU on the target system.
(CVE-2014-0118)

A denial of service flaw was found in the way httpd's mod_cgid module
executed CGI scripts that did not read data from the standard input. A
remote attacker could submit a specially crafted request that would
cause the httpd child process to hang indefinitely. (CVE-2014-0231)

All httpd users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, the httpd daemon will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020442.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5e3a583"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0226");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"httpd-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"httpd-devel-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"httpd-manual-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"httpd-tools-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_ldap-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_session-2.4.6-18.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_ssl-2.4.6-18.el7.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / mod_ldap / etc");
}
