#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1287 and 
# CentOS Errata and Security Advisory 2015:1287 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85011);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-2015");
  script_bugtraq_id(65581);
  script_xref(name:"RHSA", value:"2015:1287");

  script_name(english:"CentOS 6 : freeradius (CESA-2015:1287)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

A stack-based buffer overflow was found in the way the FreeRADIUS
rlm_pap module handled long password hashes. An attacker able to make
radiusd process a malformed password hash could cause the daemon to
crash. (CVE-2014-2015)

The freeradius packages have been upgraded to upstream version 2.2.6,
which provides a number of bug fixes and enhancements over the
previous version, including :

* The number of dictionaries have been updated.

* This update implements several Extensible Authentication Protocol
(EAP) improvements.

* A number of new expansions have been added, including:
%{randstr:...}, %{hex:...}, %{sha1:...}, %{base64:...},
%{tobase64:...}, and %{base64tohex:...}.

* Hexadecimal numbers (0x...) are now supported in %{expr:...}
expansions.

* This update adds operator support to the rlm_python module.

* The Dynamic Host Configuration Protocol (DHCP) and DHCP relay code
have been finalized.

* This update adds the rlm_cache module to cache arbitrary attributes.

For a complete list of bug fixes and enhancements provided by this
rebase, see the freeradius changelog linked to in the References
section.

(BZ#1078736)

This update also fixes the following bugs :

* The /var/log/radius/radutmp file was configured to rotate at
one-month intervals, even though this was unnecessary. This update
removes /var/log/radius/radutmp from the installed logrotate utility
configuration in the /etc/logrotate.d/radiusd file, and
/var/log/radius/radutmp is no longer rotated. (BZ#904578)

* The radiusd service could not write the output file created by the
raddebug utility. The raddebug utility now sets appropriate ownership
to the output file, allowing radiusd to write the output. (BZ#921563)

* After starting raddebug using the 'raddebug -t 0' command, raddebug
exited immediately. A typo in the special case comparison has been
fixed, and raddebug now runs for 11.5 days in this situation.
(BZ#921567)

* MS-CHAP authentication failed when the User-Name and
MS-CHAP-User-Name attributes used different encodings, even when the
user provided correct credentials. Now, MS-CHAP authentication
properly handles mismatching character encodings. Authentication with
correct credentials no longer fails in this situation. (BZ#1060319)

* Automatically generated default certificates used the SHA-1
algorithm message digest, which is considered insecure. The default
certificates now use the more secure SHA-256 algorithm message digest.
(BZ#1135439)

* During the Online Certificate Status Protocol (OCSP) validation,
radiusd terminated unexpectedly with a segmentation fault after
attempting to access the next update field that was not provided by
the OCSP responder. Now, radiusd does not crash in this situation and
instead continues to complete the OCSP validation. (BZ#1142669)

* Prior to this update, radiusd failed to work with some of the more
recent MikroTIK attributes, because the installed directory.mikrotik
file did not include them. This update adds MikroTIK attributes with
IDs up to 22 to dictionary.mikrotik, and radiusd now works as expected
with these attributes. (BZ#1173388)

Users of freeradius are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. After
installing this update, the radiusd service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-July/001899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecc5e6eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2015");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
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
if (rpm_check(release:"CentOS-6", reference:"freeradius-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-krb5-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-ldap-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-mysql-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-perl-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-postgresql-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-python-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-unixODBC-2.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freeradius-utils-2.2.6-4.el6")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-krb5 / freeradius-ldap / freeradius-mysql / etc");
}
