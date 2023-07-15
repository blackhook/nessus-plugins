#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0661 and 
# CentOS Errata and Security Advisory 2006:0661 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22321);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-4339");
  script_bugtraq_id(19849);
  script_xref(name:"RHSA", value:"2006:0661");

  script_name(english:"CentOS 3 / 4 : openssl (CESA-2006:0661)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages are now available to correct a security
issue.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The OpenSSL toolkit provides support for secure communications between
machines. OpenSSL includes a certificate management tool and shared
libraries which provide various cryptographic algorithms and
protocols.

Daniel Bleichenbacher recently described an attack on PKCS #1 v1.5
signatures. Where an RSA key with exponent 3 is used it may be
possible for an attacker to forge a PKCS #1 v1.5 signature that would
be incorrectly verified by implementations that do not check for
excess data in the RSA exponentiation result of the signature.

The Google Security Team discovered that OpenSSL is vulnerable to this
attack. This issue affects applications that use OpenSSL to verify
X.509 certificates as well as other uses of PKCS #1 v1.5.
(CVE-2006-4339)

This errata also resolves a problem where a customized ca-bundle.crt
file was overwritten when the openssl package was upgraded.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct this issue.

Note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f890821"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013204.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a79cc36"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013206.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2480290d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013208.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61446cd7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00e53b6b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e873080"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/12");
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
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.18")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.43")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssl-0.9.7a-43.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl-devel-0.9.7a-43.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl-perl-0.9.7a-43.11")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl096b-0.9.6b-22.43")) flag++;


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
