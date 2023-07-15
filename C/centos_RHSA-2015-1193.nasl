#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1193 and 
# CentOS Errata and Security Advisory 2015:1193 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84445);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0252");
  script_bugtraq_id(73252);
  script_xref(name:"RHSA", value:"2015:1193");

  script_name(english:"CentOS 7 : xerces-c (CESA-2015:1193)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xerces-c package that fixes one security issue is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Xerces-C is a validating XML parser written in a portable subset of
C++.

A flaw was found in the way the Xerces-C XML parser processed certain
XML documents. A remote attacker could provide specially crafted XML
input that, when parsed by an application using Xerces-C, would cause
that application to crash. (CVE-2015-0252)

All xerces-c users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-June/021228.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19d44b92"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-c packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0252");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-3.1.1-7.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-devel-3.1.1-7.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-doc-3.1.1-7.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-c / xerces-c-devel / xerces-c-doc");
}
