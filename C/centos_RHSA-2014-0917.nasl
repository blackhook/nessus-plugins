#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0917 and 
# CentOS Errata and Security Advisory 2014:0917 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76686);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545");
  script_bugtraq_id(64944, 65332, 65335, 66356, 67975, 68816);
  script_xref(name:"RHSA", value:"2014:0917");

  script_name(english:"CentOS 6 : nspr / nss / nss-util (CESA-2014:0917)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A race condition was found in the way NSS verified certain
certificates. A remote attacker could use this flaw to crash an
application using NSS or, possibly, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1544)

A flaw was found in the way TLS False Start was implemented in NSS. An
attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to
crash an application using NSS or, in rare cases, execute arbitrary
code with the privileges of the user running that application.
(CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or,
possibly, execute arbitrary code with the privileges of the user
running that application. This NSPR flaw was not exposed to web
content in any shipped version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain
Names in Applications (IDNA) hostname matching in NSS did not follow
the RFC 6125 recommendations. This could lead to certain invalid
certificates with international characters to be accepted as valid.
(CVE-2014-1492)

Red Hat would like to thank the Mozilla project for reporting the
CVE-2014-1544, CVE-2014-1490, CVE-2014-1491, and CVE-2014-1545 issues.
Upstream acknowledges Tyson Smith and Jesse Schwartzentruber as the
original reporters of CVE-2014-1544, Brian Smith as the original
reporter of CVE-2014-1490, Antoine Delignat-Lavaud and Karthikeyan
Bhargavan as the original reporters of CVE-2014-1491, and Abhishek
Arya as the original reporter of CVE-2014-1545.

In addition, the nss package has been upgraded to upstream version
3.16.1, and the nspr package has been upgraded to upstream version
4.10.6. These updated packages provide a number of bug fixes and
enhancements over the previous versions. (BZ#1112136, BZ#1112135)

Users of NSS and NSPR are advised to upgrade to these updated
packages, which correct these issues and add these enhancements. After
installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020434.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?161fdcc2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020436.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b9dd993"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-July/020437.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33cc54de"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr, nss and / or nss-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1544");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"nspr-4.10.6-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nspr-devel-4.10.6-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-devel-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-pkcs11-devel-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-sysinit-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-tools-3.16.1-4.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-3.16.1-1.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nss-util-devel-3.16.1-1.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / etc");
}
