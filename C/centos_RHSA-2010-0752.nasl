#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0752 and 
# CentOS Errata and Security Advisory 2010:0752 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49811);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");
  script_xref(name:"RHSA", value:"2010:0752");

  script_name(english:"CentOS 4 : gpdf (CESA-2010:0752)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gpdf package that fixes two security issues is now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

GPdf is a viewer for Portable Document Format (PDF) files.

An uninitialized pointer use flaw was discovered in GPdf. An attacker
could create a malicious PDF file that, when opened, would cause GPdf
to crash or, potentially, execute arbitrary code. (CVE-2010-3702)

An array index error was found in the way GPdf parsed PostScript Type
1 fonts embedded in PDF documents. An attacker could create a
malicious PDF file that, when opened, would cause GPdf to crash or,
potentially, execute arbitrary code. (CVE-2010-3704)

Users are advised to upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e400103e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-October/017050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5162cf37"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gpdf-2.8.2-7.7.2.el4_8.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gpdf-2.8.2-7.7.2.el4_8.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpdf");
}
