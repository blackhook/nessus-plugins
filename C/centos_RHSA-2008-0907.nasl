#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0907 and 
# CentOS Errata and Security Advisory 2008:0907 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43712);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3825");
  script_xref(name:"RHSA", value:"2008:0907");

  script_name(english:"CentOS 5 : pam_krb5 (CESA-2008:0907)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated pam_krb5 package that fixes a security issue is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The pam_krb5 module allows Pluggable Authentication Modules (PAM)
aware applications to use Kerberos to verify user identities by
obtaining user credentials at log in time.

A flaw was found in the pam_krb5 'existing_ticket' configuration
option. If a system is configured to use an existing credential cache
via the 'existing_ticket' option, it may be possible for a local user
to gain elevated privileges by using a different, local user's
credential cache. (CVE-2008-3825)

Red Hat would like to thank Stephane Bertin for responsibly
disclosing this issue.

Users of pam_krb5 should upgrade to this updated package, which
contains a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015305.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8225e1e7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c7a0b40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam_krb5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pam_krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"pam_krb5-2.2.14-1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam_krb5");
}