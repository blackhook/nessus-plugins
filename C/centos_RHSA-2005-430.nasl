#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:430 and 
# CentOS Errata and Security Advisory 2005:430 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21938);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1431");
  script_xref(name:"RHSA", value:"2005:430");

  script_name(english:"CentOS 4 : gnutls (CESA-2005:430)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated GnuTLS packages that fix a remote denial of service
vulnerability are available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GnuTLS library implements Secure Sockets Layer (SSL v3) and
Transport Layer Security (TLS v1) protocols.

A denial of service bug was found in the GnuTLS library versions prior
to 1.0.25. A remote attacker could perform a carefully crafted TLS
handshake against a service that uses the GnuTLS library causing the
service to crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1431 to this issue.

All users of GnuTLS are advised to upgrade to these updated packages
and to restart any services which use GnuTLS."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d95d6027"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94f49b45"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011783.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ead7b40f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"gnutls-1.0.20-3.2.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gnutls-devel-1.0.20-3.2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel");
}
