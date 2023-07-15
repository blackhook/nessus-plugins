#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0813 and 
# CentOS Errata and Security Advisory 2012:0813 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59923);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0833");
  script_bugtraq_id(52044);
  script_xref(name:"RHSA", value:"2012:0813");

  script_name(english:"CentOS 6 : 389-ds-base (CESA-2012:0813)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

A flaw was found in the way the 389 Directory Server daemon (ns-slapd)
handled access control instructions (ACIs) using certificate groups.
If an LDAP user that had a certificate group defined attempted to bind
to the directory server, it would cause ns-slapd to enter an infinite
loop and consume an excessive amount of CPU time. (CVE-2012-0833)

Red Hat would like to thank Graham Leggett for reporting this issue.

These updated 389-ds-base packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.3
Technical Notes for information on the most significant of these
changes.

Users are advised to upgrade to these updated 389-ds-base packages,
which resolve these issues and add these enhancements. After
installing this update, the 389 server service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ffa9cc2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0833");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.10.2-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.10.2-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.10.2-15.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
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
