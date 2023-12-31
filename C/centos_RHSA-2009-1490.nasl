#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1490 and 
# CentOS Errata and Security Advisory 2009:1490 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42071);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2964");
  script_bugtraq_id(36196);
  script_xref(name:"RHSA", value:"2009:1490");

  script_name(english:"CentOS 3 / 4 : squirrelmail (CESA-2009:1490)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes several security issues is
now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is a standards-based webmail package written in PHP.

Form submissions in SquirrelMail did not implement protection against
Cross-Site Request Forgery (CSRF) attacks. If a remote attacker
tricked a user into visiting a malicious web page, the attacker could
hijack that user's authentication, inject malicious content into that
user's preferences, or possibly send mail without that user's
permission. (CVE-2009-2964)

Users of SquirrelMail should upgrade to this updated package, which
contains a backported patch to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016181.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47e6f08f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016182.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a30b9c2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3723943"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016186.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e2bf560"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"squirrelmail-1.4.8-16.el3.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"squirrelmail-1.4.8-16.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"squirrelmail-1.4.8-5.el4_8.8")) flag++;


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
