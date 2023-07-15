#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1457 and 
# CentOS Errata and Security Advisory 2015:1457 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85023);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_bugtraq_id(73119, 73162, 73317);
  script_xref(name:"RHSA", value:"2015:1457");

  script_name(english:"CentOS 6 : gnutls (CESA-2015:1457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix three security issues and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was found that GnuTLS did not check activation and expiration dates
of CA certificates. This could cause an application using GnuTLS to
incorrectly accept a certificate as valid when its issuing CA is
already expired. (CVE-2014-8155)

It was found that GnuTLS did not verify whether a hashing algorithm
listed in a signature matched the hashing algorithm listed in the
certificate. An attacker could create a certificate that used a
different hashing algorithm than it claimed, possibly causing GnuTLS
to use an insecure, disallowed hashing algorithm during certificate
verification. (CVE-2015-0282)

It was discovered that GnuTLS did not check if all sections of X.509
certificates indicate the same signature algorithm. This flaw, in
combination with a different flaw, could possibly lead to a bypass of
the certificate signature check. (CVE-2015-0294)

The CVE-2014-8155 issue was discovered by Marcel Kolaja of Red Hat.
The CVE-2015-0282 and CVE-2015-0294 issues were discovered by Nikos
Mavrogiannopoulos of the Red Hat Security Technologies Team.

This update also fixes the following bug :

* Previously, under certain circumstances, the certtool utility could
generate X.509 certificates which contained a negative modulus.
Consequently, such certificates could have interoperation problems
with the software using them. The bug has been fixed, and certtool no
longer generates X.509 certificates containing a negative modulus.
(BZ#1036385)

Users of gnutls are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-July/001937.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcff61df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0282");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"gnutls-2.8.5-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-devel-2.8.5-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-guile-2.8.5-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-utils-2.8.5-18.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel / gnutls-guile / gnutls-utils");
}
