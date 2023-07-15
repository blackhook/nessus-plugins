#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0414 and 
# CentOS Errata and Security Advisory 2018:0414 respectively.
#

include("compat.inc");

if (description)
{
  script_id(107273);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-15135", "CVE-2018-1054");
  script_xref(name:"RHSA", value:"2018:0414");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2018:0414)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for 389-ds-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* 389-ds-base: remote Denial of Service (DoS) via search filters in
SetUnicodeStringFromUTF_8 in collate.c (CVE-2018-1054)

* 389-ds-base: Authentication bypass due to lack of size check in
slapi_ct_memcmp function in ch_malloc.c (CVE-2017-15135)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

The CVE-2017-15135 issue was discovered by Martin Poole (Red Hat).

Bug Fix(es) :

* Previously, if an administrator configured an index for an attribute
with a specific matching rule in the 'nsMatchingRule' parameter,
Directory Server did not use the retrieved indexer. As a consequence,
Directory Server did not index the values of this attribute with the
specified matching rules, and searches with extended filters were
unindexed. With this update, Directory Server uses the retrieved
indexer that processes the specified matching rule. As a result,
searches using extended filters with a specified matching rule are now
indexed. (BZ#1536343)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-March/022784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a9e0c6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1054");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-28.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-28.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-28.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-28.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs / etc");
}
