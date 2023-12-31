#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:766 and 
# CentOS Errata and Security Advisory 2005:766 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21855);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-2479", "CVE-2005-2794", "CVE-2005-2796");
  script_xref(name:"RHSA", value:"2005:766");

  script_name(english:"CentOS 3 / 4 : squid (CESA-2005:766)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Squid package that fixes security issues is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Squid is a full-featured Web proxy cache.

A bug was found in the way Squid displays error messages. A remote
attacker could submit a request containing an invalid hostname which
would result in Squid displaying a previously used error message. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-2479 to this issue.

Two denial of service bugs were found in the way Squid handles
malformed requests. A remote attacker could submit a specially crafted
request to Squid that would cause the server to crash. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-2794 and CVE-2005-2796 to these issues.

Please note that CVE-2005-2796 does not affect Red Hat Enterprise
Linux 2.1

Users of Squid should upgrade to this updated package that contains
backported patches, and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec5294a6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d2d8c91"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?694bcc7b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8caab0d4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ca177e0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-September/012173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98a925a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/15");
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
if (rpm_check(release:"CentOS-3", reference:"squid-2.5.STABLE3-6.3E.14")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squid-2.5.STABLE6-3.4E.11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
