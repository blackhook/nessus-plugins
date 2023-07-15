#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0587 and 
# CentOS Errata and Security Advisory 2013:0587 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65061);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(55704, 57755, 57778);
  script_xref(name:"RHSA", value:"2013:0587");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"CentOS 5 / 6 : openssl (CESA-2013:0587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when CBC-mode
cipher suites were used. A remote attacker could possibly use this
flaw to retrieve plain text from the encrypted packets by using a
TLS/SSL or DTLS server as a padding oracle. (CVE-2013-0169)

A NULL pointer dereference flaw was found in the OCSP response
verification in OpenSSL. A malicious OCSP server could use this flaw
to crash applications performing OCSP verification by sending a
specially crafted response. (CVE-2013-0166)

It was discovered that the TLS/SSL protocol could leak information
about plain text when optional compression was used. An attacker able
to control part of the plain text sent over an encrypted TLS/SSL
connection could possibly use this flaw to recover other portions of
the plain text. (CVE-2012-4929)

Note: This update disables zlib compression, which was previously
enabled in OpenSSL by default. Applications using OpenSSL now need to
explicitly enable zlib compression to use it.

It was found that OpenSSL read certain environment variables even when
used by a privileged (setuid or setgid) application. A local attacker
could use this flaw to escalate their privileges. No application
shipped with Red Hat Enterprise Linux 5 and 6 was affected by this
problem. (BZ#839735)

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted.");
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019264.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c72720");
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019630.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bee2b33");
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-March/000819.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e53c11b");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-26.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.0-27.el6_4.2")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl-static");
}
