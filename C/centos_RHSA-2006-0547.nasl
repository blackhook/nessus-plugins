#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0547 and 
# CentOS Errata and Security Advisory 2006:0547 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22001);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2842");
  script_xref(name:"RHSA", value:"2006:0547");

  script_name(english:"CentOS 3 / 4 : squirrelmail (CESA-2006:0547)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes a local file disclosure
flaw is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP4.

A local file disclosure flaw was found in the way SquirrelMail loads
plugins. In SquirrelMail 1.4.6 or earlier, if register_globals is on
and magic_quotes_gpc is off, it became possible for an unauthenticated
remote user to view the contents of arbitrary local files the web
server has read-access to. This configuration is neither default nor
safe, and configuring PHP with the register_globals set on is
dangerous and not recommended. (CVE-2006-2842)

Users of SquirrelMail should upgrade to this erratum package, which
contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1854b3c1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?652d0c9e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0aadb8c3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46d07622"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1733194"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/012988.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88aec6a8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (rpm_check(release:"CentOS-3", reference:"squirrelmail-1.4.6-7.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squirrelmail-1.4.6-7.el4.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
