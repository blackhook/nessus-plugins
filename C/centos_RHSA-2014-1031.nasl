#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1031 and 
# CentOS Errata and Security Advisory 2014:1031 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77059);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3562");
  script_bugtraq_id(69149);
  script_xref(name:"RHSA", value:"2014:1031");

  script_name(english:"CentOS 6 / 7 : 389-ds-base (CESA-2014:1031)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

It was found that when replication was enabled for each attribute in
389 Directory Server, which is the default configuration, the server
returned replicated metadata when the directory was searched while
debugging was enabled. A remote attacker could use this flaw to
disclose potentially sensitive information. (CVE-2014-3562)

This issue was discovered by Ludwig Krispenz of Red Hat.

All 389-ds-base users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing this update, the 389 server service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df4781c6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f22c85e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3562");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.11.15-34.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.11.15-34.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.11.15-34.el6_5")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.1.6-26.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.1.6-26.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.1.6-26.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
