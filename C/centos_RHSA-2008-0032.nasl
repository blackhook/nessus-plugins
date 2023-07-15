#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0032 and 
# CentOS Errata and Security Advisory 2008:0032 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29932);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6284");
  script_bugtraq_id(27248);
  script_xref(name:"RHSA", value:"2008:0032");

  script_name(english:"CentOS 3 / 4 / 5 : libxml2 (CESA-2008:0032)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libxml2 packages provide a library that allows you to manipulate
XML files. It includes support to read, modify, and write XML and HTML
files.

A denial of service flaw was found in the way libxml2 processes
certain content. If an application linked against libxml2 processes
malformed XML content, it could cause the application to stop
responding. (CVE-2007-6284)

Red Hat would like to thank the Google Security Team for responsibly
disclosing this issue.

All users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014569.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b941f889"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014570.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04b9e0cb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014573.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f107fda"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014575.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbd0a3b2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02dd2ee0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d198785d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?def30a99"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-January/014602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27463af9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"libxml2-2.5.10-8")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-devel-2.5.10-8")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxml2-python-2.5.10-8")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libxml2-2.6.16-10.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-devel-2.6.16-10.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libxml2-python-2.6.16-10.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python");
}
