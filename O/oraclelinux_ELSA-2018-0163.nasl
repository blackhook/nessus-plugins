#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0163 and 
# Oracle Linux Security Advisory ELSA-2018-0163 respectively.
#

include("compat.inc");

if (description)
{
  script_id(106366);
  script_version("3.6");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2017-15134");
  script_xref(name:"RHSA", value:"2018:0163");

  script_name(english:"Oracle Linux 7 : 389-ds-base (ELSA-2018-0163)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:0163 :

An update for 389-ds-base is now available for Red Hat Enterprise
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-January/007485.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.6.1-26.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.6.1-26.el7_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs / etc");
}
