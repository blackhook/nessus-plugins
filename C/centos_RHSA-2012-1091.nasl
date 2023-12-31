#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1091 and 
# CentOS Errata and Security Advisory 2012:1091 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60001);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0441");
  script_bugtraq_id(53798);
  script_xref(name:"RHSA", value:"2012:1091");

  script_name(english:"CentOS 6 : nss (CESA-2012:1091)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nspr packages that fix one security issue,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
decoder in NSS handled zero length items. This flaw could cause the
decoder to incorrectly skip or replace certain items with a default
value, or could cause an application to crash if, for example, it
received a specially crafted OCSP (Online Certificate Status Protocol)
response. (CVE-2012-0441)

The nspr package has been upgraded to upstream version 4.9.1, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#833762)

The nss-util package has been upgraded to upstream version 3.13.5,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#833763)

The nss package has been upgraded to upstream version 3.13.5, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#834100)

All NSS, NSPR, and nss-util users are advised to upgrade to these
updated packages, which correct these issues and add these
enhancements. After installing this update, applications using NSS,
NSPR, or nss-util must be restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde1b710"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0441");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
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
if (rpm_check(release:"CentOS-6", reference:"nspr-4.9.1-2.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nspr-devel-4.9.1-2.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.13.5-1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.13.5-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
