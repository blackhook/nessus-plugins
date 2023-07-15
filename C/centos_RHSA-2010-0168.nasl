#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0168 and 
# CentOS Errata and Security Advisory 2010:0168 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45367);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0408", "CVE-2010-0434");
  script_bugtraq_id(38491, 38580);
  script_xref(name:"RHSA", value:"2010:0168");

  script_name(english:"CentOS 5 : httpd (CESA-2010:0168)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues and add an
enhancement are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Apache HTTP Server is a popular web server.

It was discovered that mod_proxy_ajp incorrectly returned an 'Internal
Server Error' response when processing certain malformed requests,
which caused the back-end server to be marked as failed in
configurations where mod_proxy is used in load balancer mode. A remote
attacker could cause mod_proxy to not send requests to back-end AJP
(Apache JServ Protocol) servers for the retry timeout period (60
seconds by default) by sending specially crafted requests.
(CVE-2010-0408)

A use-after-free flaw was discovered in the way the Apache HTTP Server
handled request headers in subrequests. In configurations where
subrequests are used, a multithreaded MPM (Multi-Processing Module)
could possibly leak information from other requests in request
replies. (CVE-2010-0434)

This update also adds the following enhancement :

* with the updated openssl packages from RHSA-2010:0162 installed,
mod_ssl will refuse to renegotiate a TLS/SSL connection with an
unpatched client that does not support RFC 5746. This update adds the
'SSLInsecureRenegotiation' configuration directive. If this directive
is enabled, mod_ssl will renegotiate insecurely with unpatched
clients. (BZ#567980)

Refer to the following Red Hat Knowledgebase article for more details
about the changed mod_ssl behavior:
http://kbase.redhat.com/faq/docs/DOC-20491

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. After installing the updated packages, the httpd daemon
must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c47205e8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-March/016604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55d08bec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-31.el5.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-31.el5.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-31.el5.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-31.el5.centos.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
}
