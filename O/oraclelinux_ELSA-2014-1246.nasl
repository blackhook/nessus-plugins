#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1246 and 
# Oracle Linux Security Advisory ELSA-2014-1246 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77739);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1545");
  script_bugtraq_id(64944, 65332, 65335, 66356, 67975);
  script_xref(name:"RHSA", value:"2014:1246");

  script_name(english:"Oracle Linux 5 : nspr / nss (ELSA-2014-1246)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1246 :

Updated nss and nspr packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

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
CVE-2014-1490, CVE-2014-1491, and CVE-2014-1545 issues. Upstream
acknowledges Brian Smith as the original reporter of CVE-2014-1490,
Antoine Delignat-Lavaud and Karthikeyan Bhargavan as the original
reporters of CVE-2014-1491, and Abhishek Arya as the original reporter
of CVE-2014-1545.

The nss and nspr packages have been upgraded to upstream version
3.16.1 and 4.10.6 respectively, which provide a number of bug fixes
and enhancements over the previous versions. (BZ#1110857, BZ#1110860)

This update also fixes the following bugs :

* Previously, when the output.log file was not present on the system,
the shell in the Network Security Services (NSS) specification handled
test failures incorrectly as false positive test results.
Consequently, certain utilities, such as 'grep', could not handle
failures properly. This update improves error detection in the
specification file, and 'grep' and other utilities now handle missing
files or crashes as intended. (BZ#1035281)

* Prior to this update, a subordinate Certificate Authority (CA) of
the ANSSI agency incorrectly issued an intermediate certificate
installed on a network monitoring device. As a consequence, the
monitoring device was enabled to act as an MITM (Man in the Middle)
proxy performing traffic management of domain names or IP addresses
that the certificate holder did not own or control. The trust in the
intermediate certificate to issue the certificate for an MITM device
has been revoked, and such a device can no longer be used for MITM
attacks. (BZ#1042684)

* Due to a regression, MD5 certificates were rejected by default
because Network Security Services (NSS) did not trust MD5
certificates. With this update, MD5 certificates are supported in Red
Hat Enterprise Linux 5. (BZ#11015864)

Users of nss and nspr are advised to upgrade to these updated
packages, which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-September/004456.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"nss-3.16.1-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.16.1-2.el5")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.16.1-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-devel / nss-pkcs11-devel / nss-tools");
}
