#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1653 and 
# CentOS Errata and Security Advisory 2014:1653 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78517);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"RHSA", value:"2014:1653");

  script_name(english:"CentOS 5 : openssl (CESA-2014:1653) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated openssl packages that contain a backported patch to mitigate
the CVE-2014-3566 issue are now available for Red Hat Enterprise Linux
5.

Red Hat Product Security has rated this update as having Moderate
security impact.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
Transport Layer Security (TLS), and Datagram Transport Layer Security
(DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

This update adds support for the TLS Fallback Signaling Cipher Suite
Value (TLS_FALLBACK_SCSV), which can be used to prevent protocol
downgrade attacks against applications which re-connect using a lower
SSL/TLS protocol version when the initial connection indicating the
highest supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC)
mode. This issue is identified as CVE-2014-3566, and also known under
the alias POODLE. This SSL 3.0 protocol flaw will not be addressed in
a future update; it is recommended that users configure their
applications to require at least TLS protocol version 1.0 for secure
communication.

For additional information about this flaw, see the Knowledgebase
article at https://access.redhat.com/articles/1232123

All OpenSSL users are advised to upgrade to these updated packages,
which contain a backported patch to mitigate the CVE-2014-3566 issue.
For the update to take effect, all services linked to the OpenSSL
library (such as httpd and other SSL-enabled services) must be
restarted or the system rebooted.");
  # https://lists.centos.org/pipermail/centos-announce/2014-October/020693.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a785d5aa");
  # https://lists.centos.org/pipermail/centos-announce/2014-October/020696.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0e102e8");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"openssl-0.9.8e-31.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-devel-0.9.8e-31.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openssl-perl-0.9.8e-31.el5_11")) flag++;


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
