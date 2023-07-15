#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0057 and 
# CentOS Errata and Security Advisory 2009:0057 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35424);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0030", "CVE-2009-1580");
  script_xref(name:"RHSA", value:"2009:0057");

  script_name(english:"CentOS 3 / 4 / 5 : squirrelmail (CESA-2009:0057)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes a security issue is now
available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SquirrelMail is an easy-to-configure, standards-based, webmail package
written in PHP. It includes built-in PHP support for the IMAP and SMTP
protocols, and pure HTML 4.0 page-rendering (with no JavaScript
required) for maximum browser-compatibility, strong MIME support,
address books, and folder manipulation.

The Red Hat SquirrelMail packages provided by the RHSA-2009:0010
advisory introduced a session handling flaw. Users who logged back
into SquirrelMail without restarting their web browsers were assigned
fixed session identifiers. A remote attacker could make use of that
flaw to hijack user sessions. (CVE-2009-0030)

SquirrelMail users should upgrade to this updated package, which
contains a patch to correct this issue. As well, all users who used
affected versions of SquirrelMail should review their preferences."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a868e48a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa401b2a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63a8621c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ddebb73"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b94db27"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-January/015567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2516b23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"squirrelmail-1.4.8-9.el3.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"squirrelmail-1.4.8-9.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squirrelmail-1.4.8-5.el4.centos.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squirrelmail-1.4.8-5.el4.centos.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-5.el5.centos.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
