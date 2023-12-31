#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0659 and 
# CentOS Errata and Security Advisory 2010:0659 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67078);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1452", "CVE-2010-2068", "CVE-2010-2791");
  script_bugtraq_id(41963, 42102);
  script_xref(name:"RHSA", value:"2010:0659");

  script_name(english:"CentOS 5 : httpd (CESA-2010:0659)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues and multiple bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Apache HTTP Server is a popular web server.

A flaw was discovered in the way the mod_proxy module of the Apache
HTTP Server handled the timeouts of requests forwarded by a reverse
proxy to the back-end server. If the proxy was configured to reuse
existing back-end connections, it could return a response intended for
another user under certain timeout conditions, possibly leading to
information disclosure. (CVE-2010-2791)

A flaw was found in the way the mod_dav module of the Apache HTTP
Server handled certain requests. If a remote attacker were to send a
carefully crafted request to the server, it could cause the httpd
child process to crash. (CVE-2010-1452)

This update also fixes the following bugs :

* numerous issues in the INFLATE filter provided by mod_deflate.
'Inflate error -5 on flush' errors may have been logged. This update
upgrades mod_deflate to the newer upstream version from Apache HTTP
Server 2.2.15. (BZ#625435)

* the response would be corrupted if mod_filter applied the DEFLATE
filter to a resource requiring a subrequest with an internal redirect.
(BZ#625451)

* the OID() function used in the mod_ssl 'SSLRequire' directive did
not correctly evaluate extensions of an unknown type. (BZ#625452)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?032c0c92"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fddb810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-43.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-43.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-43.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-43.el5.centos.3")) flag++;


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
