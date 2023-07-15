#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:518 and 
# CentOS Errata and Security Advisory 2005:518 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21836);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1269", "CVE-2005-1934");
  script_xref(name:"RHSA", value:"2005:518");

  script_name(english:"CentOS 3 / 4 : gaim (CESA-2005:518)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes two denial of service issues is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Gaim application is a multi-protocol instant messaging client.

Jacopo Ottaviani discovered a bug in the way Gaim handles Yahoo!
Messenger file transfers. It is possible for a malicious user to send
a specially crafted file transfer request that causes Gaim to crash.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-1269 to this issue.

Additionally, Hugo de Bokkenrijder discovered a bug in the way Gaim
parses MSN Messenger messages. It is possible for a malicious user to
send a specially crafted MSN Messenger message that causes Gaim to
crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1934 to this issue.

Users of gaim are advised to upgrade to this updated package, which
contains version 1.3.1 and is not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ced2441e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd2203d4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f425ad9d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee741085"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afae10a2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011884.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b422f2d3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/16");
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
if (rpm_check(release:"CentOS-3", reference:"gaim-1.3.1-0.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gaim-1.3.1-0.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gaim");
}
