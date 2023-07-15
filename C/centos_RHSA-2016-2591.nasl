#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2591 and 
# CentOS Errata and Security Advisory 2016:2591 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95337);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2016-3119", "CVE-2016-3120");
  script_xref(name:"RHSA", value:"2016:2591");
  script_xref(name:"IAVB", value:"2016-B-0115-S");

  script_name(english:"CentOS 7 : krb5 (CESA-2016:2591)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for krb5 is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Kerberos is a network authentication system, which can improve the
security of your network by eliminating the insecure practice of
sending passwords over the network in unencrypted form. It allows
clients and servers to authenticate to each other with the help of a
trusted third party, the Kerberos key distribution center (KDC).

The following packages have been upgraded to a newer upstream version:
krb5 (1.14.1). (BZ#1292153)

Security Fix(es) :

* A NULL pointer dereference flaw was found in MIT Kerberos kadmind
service. An authenticated attacker with permission to modify a
principal entry could use this flaw to cause kadmind to dereference a
NULL pointer and crash by supplying an empty DB argument to the
modify_principal command, if kadmind was configured to use the LDAP
KDB module. (CVE-2016-3119)

* A NULL pointer dereference flaw was found in MIT Kerberos krb5kdc
service. An authenticated attacker could use this flaw to cause
krb5kdc to dereference a NULL pointer and crash by making an S4U2Self
request, if the restrict_anonymous_to_tgt option was set to true.
(CVE-2016-3120)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003271.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11369aec");
  script_set_attribute(attribute:"solution", value:
"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libkadm5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-devel-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-libs-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-pkinit-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-server-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-server-ldap-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"krb5-workstation-1.14.1-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libkadm5-1.14.1-26.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
