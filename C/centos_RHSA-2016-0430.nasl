#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0430 and 
# CentOS Errata and Security Advisory 2016:0430 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89850);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-0729");
  script_xref(name:"RHSA", value:"2016:0430");

  script_name(english:"CentOS 7 : xerces-c (CESA-2016:0430)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xerces-c packages that fix one security issue are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Xerces-C is a validating XML parser written in a portable subset of
C++.

It was discovered that the Xerces-C XML parser did not properly
process certain XML input. By providing specially crafted XML data to
an application using Xerces-C for XML processing, a remote attacker
could exploit this flaw to cause an application crash or, possibly,
execute arbitrary code with the privileges of the application.
(CVE-2016-0729)

Red Hat would like to thank Gustavo Grieco for reporting this issue.

All xerces-c users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, all applications using Xerces-C must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-March/021729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82d37901"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-c packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0729");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xerces-c-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-3.1.1-8.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-devel-3.1.1-8.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xerces-c-doc-3.1.1-8.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-c / xerces-c-devel / xerces-c-doc");
}
