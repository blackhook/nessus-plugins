#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:415 and 
# CentOS Errata and Security Advisory 2005:415 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21822);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-1999-0710", "CVE-2005-0626", "CVE-2005-0718", "CVE-2005-1345", "CVE-2005-1519");
  script_xref(name:"RHSA", value:"2005:415");

  script_name(english:"CentOS 3 / 4 : squid (CESA-2005:415)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squid package that fixes several security issues is now
available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Squid is a full-featured Web proxy cache.

A race condition bug was found in the way Squid handles the now
obsolete Set-Cookie header. It is possible that Squid can leak
Set-Cookie header information to other clients connecting to Squid.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0626 to this issue. Please note that this
issue only affected Red Hat Enterprise Linux 4.

A bug was found in the way Squid handles PUT and POST requests. It is
possible for an authorised remote user to cause a failed PUT or POST
request which can cause Squid to crash. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0718
to this issue.

A bug was found in the way Squid processes errors in the access
control list. It is possible that an error in the access control list
could give users more access than intended. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-1345 to this issue.

A bug was found in the way Squid handles access to the cachemgr.cgi
script. It is possible for an authorised remote user to bypass access
control lists with this flaw. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-1999-0710 to this
issue.

A bug was found in the way Squid handles DNS replies. If the port
Squid uses for DNS requests is not protected by a firewall it is
possible for a remote attacker to spoof DNS replies, possibly
redirecting a user to spoofed or malicious content. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1519 to this issue.

Additionally this update fixes the following bugs: - LDAP
Authentication fails with an assertion error when using Red Hat
Enterprise Linux 4

Users of Squid should upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011857.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dd7ca5c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0807586d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?521aff2b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca2f0df9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b398b537"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011870.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?160c92ae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"squid-2.5.STABLE3-6.3E.13")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squid-2.5.STABLE6-3.4E.9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
