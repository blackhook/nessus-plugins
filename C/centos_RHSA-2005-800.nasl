#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:800 and 
# CentOS Errata and Security Advisory 2005:800 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21861);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0109", "CVE-2005-2969");
  script_xref(name:"RHSA", value:"2005:800");

  script_name(english:"CentOS 3 / 4 : openssl (CESA-2005:800)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library.

OpenSSL contained a software work-around for a bug in SSL handling in
Microsoft Internet Explorer version 3.0.2. This work-around is enabled
in most servers that use OpenSSL to provide support for SSL and TLS.
Yutaka Oiwa discovered that this work-around could allow an attacker,
acting as a 'man in the middle' to force an SSL connection to use SSL
2.0 rather than a stronger protocol such as SSL 3.0 or TLS 1.0. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-2969 to this issue.

A bug was also fixed in the way OpenSSL creates DSA signatures. A
cache timing attack was fixed in RHSA-2005-476 which caused OpenSSL to
do private key calculations with a fixed time window. The DSA fix for
this was not complete and the calculations are not always performed
within a fixed-window. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0109 to this
issue.

Users are advised to upgrade to these updated packages, which remove
the MISE 3.0.2 work-around and contain patches to correct these
issues.

Note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad41a78"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b0f60b2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34710513"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?697a76e1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.22.4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-0.9.7a-43.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-devel-0.9.7a-43.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl-perl-0.9.7a-43.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openssl096b-0.9.6b-22.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl096b");
}
