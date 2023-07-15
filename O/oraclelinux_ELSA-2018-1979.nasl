#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1979 and 
# Oracle Linux Security Advisory ELSA-2018-1979 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110750);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-1080");
  script_xref(name:"RHSA", value:"2018:1979");

  script_name(english:"Oracle Linux 7 : pki-core (ELSA-2018-1979)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:1979 :

An update for pki-core is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Public Key Infrastructure (PKI) Core contains fundamental packages
required by Red Hat Certificate System.

Security Fix(es) :

* pki-core: Mishandled ACL configuration in AAclAuthz.java reverses
rules that allow and deny access (CVE-2018-1080)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

This issue was discovered by Fraser Tweedale (Red Hat).

Bug Fix(es) :

* Previously, when ECC keys were enrolled, Certificate Management over
CMS (CMC) authentication failed with a 'TokenException: Unable to
insert certificate into temporary database' error. As a consequence,
the enrollment failed. This update fixes the problem. As a result, the
mentioned bug no longer occurs. (BZ#1550581)

* Previously, Certificate System used the same enrollment profiles for
issuing RSA and ECC certificates. As a consequence, the key usage
extension in issued certificates did not meet the Common Criteria
standard. This update adds ECC-specific enrollment profiles where the
key usage extension for TLS server and client certificates are
different as described in RFC 6960. Additionally, the update changes
existing profiles to issue only RSA certificates. As a result, the key
usage extension in ECC certificates now meets the Common Criteria
standard. (BZ#1554726)

* The Certificate System server rejects saving invalid access control
lists (ACL). As a consequence, when saving an ACL with an empty
expression, the server rejected the update and the pkiconsole utility
displayed an StringIndexOutOfBoundsException error. With this update,
the utility rejects empty ACL expressions. As a result, invalid ACLs
cannot be saved and the error is no longer displayed. (BZ#1557883)

* Previously, due to a bug in the Certificate System installation
procedure, installing a Key Recovery Authority (KRA) with ECC keys
failed. To fix the problem, the installation process has been updated
to handle both RSA and ECC subsystems automatically. As a result,
installing subsystems with ECC keys no longer fail. (BZ#1581134)

* Previously, during verification, Certificate System encoded the ECC
public key incorrectly in CMC Certificate Request Message Format
(CRMF) requests. As a consequence, requesting an ECC certificate with
Certificate Management over CMS (CMC) in CRMF failed. The problem has
been fixed, and as a result, CMC CRMF requests using ECC keys work as
expected. (BZ#1585945)

Enhancement(s) :

* The pkispawn man page has been updated and now describes the
--skip-configuration and --skip-installation parameters. (BZ#1551067)

* With this update, Certificate System adds the Subject Alternative
Name (SAN) extension by default to server certificates and sets it to
the Common Name (CN) of the certificate. (BZ#1581135)

* With this enhancement, users can create Certificate Request Message
Format (CRMF) requests without the key archival option when using the
CRMFPopClient utility. This feature increases flexibility because a
Key Recovery Authority (KRA) certificate is no longer required.
Previously, if the user did not pass the '-b
transport_certificate_file' option to CRMFPopClient, the utility
automatically used the KRA transport certificate stored in the
transport.txt file. With this update, if '-b
transport_certificate_file' is not specified, Certificate System
creates a request without using key archival. (BZ#1588945)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-June/007817.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pki-core packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-base-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-base-java-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-ca-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-javadoc-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-kra-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-server-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-symkey-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"pki-tools-10.5.1-13.1.el7_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-base / pki-base-java / pki-ca / pki-javadoc / pki-kra / etc");
}
