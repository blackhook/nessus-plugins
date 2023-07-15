#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0794 and 
# CentOS Errata and Security Advisory 2015:0794 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82667);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-5352", "CVE-2014-5353", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422");
  script_bugtraq_id(71679, 72494, 72495, 72496);
  script_xref(name:"RHSA", value:"2015:0794");

  script_name(english:"CentOS 6 : krb5 (CESA-2015:0794)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Kerberos is a networked authentication system which allows clients and
servers to authenticate to each other with the help of a trusted third
party, the Kerberos KDC.

The following security issues are fixed with this release :

A use-after-free flaw was found in the way the MIT Kerberos
libgssapi_krb5 library processed valid context deletion tokens. An
attacker able to make an application using the GSS-API library
(libgssapi) could call the gss_process_context_token() function and
use this flaw to crash that application. (CVE-2014-5352)

If kadmind were used with an LDAP back end for the KDC database, a
remote, authenticated attacker who has the permissions to set the
password policy could crash kadmind by attempting to use a named
ticket policy object as a password policy for a principal.
(CVE-2014-5353)

It was found that the krb5_read_message() function of MIT Kerberos did
not correctly sanitize input, and could create invalid krb5_data
objects. A remote, unauthenticated attacker could use this flaw to
crash a Kerberos child process via a specially crafted request.
(CVE-2014-5355)

A double-free flaw was found in the way MIT Kerberos handled invalid
External Data Representation (XDR) data. An authenticated user could
use this flaw to crash the MIT Kerberos administration server
(kadmind), or other applications using Kerberos libraries, via
specially crafted XDR packets. (CVE-2014-9421)

It was found that the MIT Kerberos administration server (kadmind)
incorrectly accepted certain authentication requests for two-component
server principal names. A remote attacker able to acquire a key with a
particularly named principal (such as 'kad/x') could use this flaw to
impersonate any user to kadmind, and perform administrative actions as
that user. (CVE-2014-9422)

Red Hat would like to thank the MIT Kerberos project for reporting
CVE-2014-5352, CVE-2014-9421, and CVE-2014-9422. The MIT Kerberos
project acknowledges Nico Williams for assisting with the analysis of
CVE-2014-5352.

All krb5 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-April/021058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e91ba7f0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5352");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"krb5-devel-1.10.3-37.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-libs-1.10.3-37.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-pkinit-openssl-1.10.3-37.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-1.10.3-37.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-ldap-1.10.3-37.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-workstation-1.10.3-37.el6_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-pkinit-openssl / krb5-server / etc");
}
