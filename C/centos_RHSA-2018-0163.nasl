#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0163 and 
# CentOS Errata and Security Advisory 2018:0163 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106355);
  script_version("3.8");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2017-15134");
  script_xref(name:"RHSA", value:"2018:0163");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2018:0163)");
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

* A stack-based buffer overflow flaw was found in the way 389-ds-base
handled certain LDAP search filters. A remote, unauthenticated
attacker could potentially use this flaw to make ns-slapd crash via a
specially crafted LDAP request, thus resulting in denial of service.
(CVE-2017-15134)

Bug Fix(es) :

* Previously, when a connection received a high operation rate,
Directory Server stopped to poll the connection in certain situations.
As a consequence, new requests on the connection were not detected and
processed. With this update, Directory Server correctly decides
whether a connection has to be polled. As a result, connections with a
high request rate no longer remain unprocessed. (BZ#1523505)

* Previously, if Directory Server was stopped during an operation
which created additional changes in the memory changelog, the
Replication Update Vector (RUV) in the changelog was higher than the
RUV in the database. As a consequence, Directory Server recreated the
changelog when the server started. With this update, the server now
writes the highest RUV to the changelog only if there is the highest
Change Sequence Number (CSN) present in it. As a result, the database
and the changelog RUV are consistent and the server does not need
recreating the changelog at start up. (BZ#1523507)

* Due to a bug, using a large number of Class of Service (CoS)
templates in Directory Server increased the virtual attribute
processing time. This update improves the structure of the CoS
storage. As a result, using a large number of CoS templates no longer
increases the virtual attribute processing time. (BZ#1526928)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-January/022719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83bc7541"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15134");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-26.el7_4")) flag++;


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
