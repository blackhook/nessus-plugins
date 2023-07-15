#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0015 and 
# CentOS Errata and Security Advisory 2014:0015 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71865);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450");
  script_xref(name:"RHSA", value:"2014:0015");

  script_name(english:"CentOS 6 : openssl (CESA-2014:0015)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A flaw was found in the way OpenSSL determined which hashing algorithm
to use when TLS protocol version 1.2 was enabled. This could possibly
cause OpenSSL to use an incorrect hashing algorithm, leading to a
crash of an application using the library. (CVE-2013-6449)

It was discovered that the Datagram Transport Layer Security (DTLS)
protocol implementation in OpenSSL did not properly maintain
encryption and digest contexts during renegotiation. A lost or
discarded renegotiation handshake packet could cause a DTLS client or
server using OpenSSL to crash. (CVE-2013-6450)

A NULL pointer dereference flaw was found in the way OpenSSL handled
TLS/SSL protocol handshake packets. A specially crafted handshake
packet could cause a TLS/SSL client using OpenSSL to crash.
(CVE-2013-4353)

All OpenSSL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-January/020102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9409c422"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6450");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/09");
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
if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.1e-16.el6_5.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.1e-16.el6_5.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.1e-16.el6_5.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.1e-16.el6_5.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl-static");
}
