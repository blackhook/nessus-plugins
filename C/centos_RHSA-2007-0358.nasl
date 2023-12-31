#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0358 and 
# CentOS Errata and Security Advisory 2007:0358 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25257);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1262", "CVE-2007-2589");
  script_xref(name:"RHSA", value:"2007:0358");

  script_name(english:"CentOS 3 / 4 / 5 : squirrelmail (CESA-2007:0358)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new squirrelmail package that fixes security issues is now available
for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP4.

Several HTML filtering bugs were discovered in SquirrelMail. An
attacker could inject arbitrary JavaScript leading to cross-site
scripting attacks by sending an e-mail viewed by a user within
SquirrelMail. (CVE-2007-1262)

Squirrelmail did not sufficiently check arguments to IMG tags in HTML
e-mail messages. This could be exploited by an attacker by sending
arbitrary e-mail messages on behalf of a squirrelmail user tricked
into opening a maliciously crafted HTML e-mail message.
(CVE-2007-2589)

Users of SquirrelMail should upgrade to this erratum package, which
contains a backported patch to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fa0b1e8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78ffc8db"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013777.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dff2ed37"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013788.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?817b7615"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013789.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea2099b6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d61655af"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e20cf8ac"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(79, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"squirrelmail-1.4.8-6.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squirrelmail-1.4.8-4.0.1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squirrelmail-1.4.8-4.0.1.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-4.0.1..el5.centos.1")) flag++;


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
