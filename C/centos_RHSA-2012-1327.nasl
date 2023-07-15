#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1327 and 
# CentOS Errata and Security Advisory 2012:1327 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62396);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-3547");
  script_bugtraq_id(55483);
  script_xref(name:"RHSA", value:"2012:1327");

  script_name(english:"CentOS 5 : freeradius2 (CESA-2012:1327)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freeradius2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

A buffer overflow flaw was discovered in the way radiusd handled the
expiration date field in X.509 client certificates. A remote attacker
could possibly use this flaw to crash radiusd if it were configured to
use the certificate or TLS tunnelled authentication methods (such as
EAP-TLS, EAP-TTLS, and PEAP). (CVE-2012-3547)

Red Hat would like to thank Timo Warns of PRESENSE Technologies GmbH
for reporting this issue.

Users of FreeRADIUS are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, radiusd will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-October/018905.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42dce170"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3547");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freeradius2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-krb5-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-ldap-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-mysql-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-perl-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-postgresql-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-python-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-unixODBC-2.1.12-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freeradius2-utils-2.1.12-4.el5_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius2 / freeradius2-krb5 / freeradius2-ldap / etc");
}
