#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0247 and 
# CentOS Errata and Security Advisory 2014:0247 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72804);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-5138", "CVE-2014-0092");
  script_bugtraq_id(65792, 65919);
  script_xref(name:"RHSA", value:"2014:0247");

  script_name(english:"CentOS 5 : gnutls (CESA-2014:0247)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was discovered that GnuTLS did not correctly handle certain errors
that could occur during the verification of an X.509 certificate,
causing it to incorrectly report a successful verification. An
attacker could use this flaw to create a specially crafted certificate
that could be accepted by GnuTLS as valid for a site chosen by the
attacker. (CVE-2014-0092)

A flaw was found in the way GnuTLS handled version 1 X.509
certificates. An attacker able to obtain a version 1 certificate from
a trusted certificate authority could use this flaw to issue
certificates for other sites that would be accepted by GnuTLS as
valid. (CVE-2009-5138)

The CVE-2014-0092 issue was discovered by Nikos Mavrogiannopoulos of
the Red Hat Security Technologies Team.

Users of GnuTLS are advised to upgrade to these updated packages,
which correct these issues. For the update to take effect, all
applications linked to the GnuTLS library must be restarted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-March/020183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d26ba6a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-5138");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"gnutls-1.4.1-14.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-devel-1.4.1-14.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-utils-1.4.1-14.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel / gnutls-utils");
}
