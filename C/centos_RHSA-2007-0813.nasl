#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0813 and 
# CentOS Errata and Security Advisory 2007:0813 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27538);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3108", "CVE-2007-5135");
  script_bugtraq_id(25831);
  script_xref(name:"RHSA", value:"2007:0813");

  script_name(english:"CentOS 3 : openssl (CESA-2007:0813)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that correct security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library.

A flaw was found in the SSL_get_shared_ciphers() utility function. An
attacker could send a list of ciphers to an application that used this
function and overrun a buffer with a single byte (CVE-2007-5135). Few
applications make use of this vulnerable function and generally it is
used only when applications are compiled for debugging.

A number of possible side-channel attacks were discovered affecting
OpenSSL. A local attacker could possibly obtain RSA private keys being
used on a system. In practice these attacks would be difficult to
perform outside of a lab environment. This update contains backported
patches designed to mitigate these issues. (CVE-2007-3108).

Users of OpenSSL should upgrade to these updated packages, which
contain backported patches to resolve these issues.

Note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1745e666"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48293b00"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014327.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3eef5729"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl");
}
