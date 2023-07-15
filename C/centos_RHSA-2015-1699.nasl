#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1699 and 
# CentOS Errata and Security Advisory 2015:1699 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86501);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-2730");
  script_xref(name:"RHSA", value:"2015:1699");

  script_name(english:"CentOS 6 / 7 : nss-softokn (CESA-2015:1699)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss-softokn packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications.

A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks.
(CVE-2015-2730)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Watson Ladd as the original reporter of
this issue.

All nss-softokn users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6569652d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021362.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e62d2f29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss-softokn packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2730");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-devel-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-3.14.3-23.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-softokn-freebl-devel-3.14.3-23.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2.3-13.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2.3-13.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss-softokn / nss-softokn-devel / nss-softokn-freebl / etc");
}
