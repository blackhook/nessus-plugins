#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1978 and 
# CentOS Errata and Security Advisory 2016:1978 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93803);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-1000111");
  script_xref(name:"RHSA", value:"2016:1978");

  script_name(english:"CentOS 6 / 7 : python-twisted-web (CESA-2016:1978)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for python-twisted-web is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Twisted is an event-based framework for internet applications. Twisted
Web is a complete web server, aimed at hosting web applications using
Twisted and Python, but fully able to serve static pages too.

Security Fix(es) :

* It was discovered that python-twisted-web used the value of the
Proxy header from HTTP requests to initialize the HTTP_PROXY
environment variable for CGI scripts, which in turn was incorrectly
used by certain HTTP client implementations to configure the proxy for
outgoing HTTP requests. A remote attacker could possibly use this flaw
to redirect HTTP requests performed by a CGI script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-1000111)

Note: After this update, python-twisted-web will no longer pass the
value of the Proxy request header to scripts via the HTTP_PROXY
environment variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-September/022099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6e2a64c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-September/022100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59dd4911"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-twisted-web package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000111");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"python-twisted-web-8.2.0-5.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-twisted-web-12.1.0-5.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-twisted-web");
}
