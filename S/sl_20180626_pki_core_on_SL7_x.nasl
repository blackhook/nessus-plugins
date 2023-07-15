#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(110719);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-1080");

  script_name(english:"Scientific Linux Security Update : pki-core on SL7.x x86_64 (20180626)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - pki-core: Mishandled ACL configuration in AAclAuthz.java
    reverses rules that allow and deny access
    (CVE-2018-1080)

Bug Fix(es) :

  - Previously, when ECC keys were enrolled, Certificate
    Management over CMS (CMC) authentication failed with a
    'TokenException: Unable to insert certificate into
    temporary database' error. As a consequence, the
    enrollment failed. This update fixes the problem. As a
    result, the mentioned bug no longer occurs.

  - Previously, Certificate System used the same enrollment
    profiles for issuing RSA and ECC certificates. As a
    consequence, the key usage extension in issued
    certificates did not meet the Common Criteria standard.
    This update adds ECC-specific enrollment profiles where
    the key usage extension for TLS server and client
    certificates are different as described in RFC 6960.
    Additionally, the update changes existing profiles to
    issue only RSA certificates. As a result, the key usage
    extension in ECC certificates now meets the Common
    Criteria standard.

  - The Certificate System server rejects saving invalid
    access control lists (ACL). As a consequence, when
    saving an ACL with an empty expression, the server
    rejected the update and the pkiconsole utility displayed
    an StringIndexOutOfBoundsException error. With this
    update, the utility rejects empty ACL expressions. As a
    result, invalid ACLs cannot be saved and the error is no
    longer displayed.

  - Previously, due to a bug in the Certificate System
    installation procedure, installing a Key Recovery
    Authority (KRA) with ECC keys failed. To fix the
    problem, the installation process has been updated to
    handle both RSA and ECC subsystems automatically. As a
    result, installing subsystems with ECC keys no longer
    fail.

  - Previously, during verification, Certificate System
    encoded the ECC public key incorrectly in CMC
    Certificate Request Message Format (CRMF) requests. As a
    consequence, requesting an ECC certificate with
    Certificate Management over CMS (CMC) in CRMF failed.
    The problem has been fixed, and as a result, CMC CRMF
    requests using ECC keys work as expected.

Enhancement(s) :

  - The pkispawn man page has been updated and now describes
    the - --skip- configuration and --skip-installation
    parameters.

  - With this update, Certificate System adds the Subject
    Alternative Name (SAN) extension by default to server
    certificates and sets it to the Common Name (CN) of the
    certificate.

  - With this enhancement, users can create Certificate
    Request Message Format (CRMF) requests without the key
    archival option when using the CRMFPopClient utility.
    This feature increases flexibility because a Key
    Recovery Authority (KRA) certificate is no longer
    required. Previously, if the user did not pass the '-b
    transport_certificate_file' option to CRMFPopClient, the
    utility automatically used the KRA transport certificate
    stored in the transport.txt file. With this update, if
    '-b transport_certificate_file' is not specified,
    Certificate System creates a request without using key
    archival."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1806&L=scientific-linux-errata&F=&S=&P=4923
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91f7eaff"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-base-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pki-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", reference:"pki-base-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"pki-base-java-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"pki-ca-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pki-core-debuginfo-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"pki-javadoc-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"pki-kra-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", reference:"pki-server-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pki-symkey-10.5.1-13.1.el7_5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pki-tools-10.5.1-13.1.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-base / pki-base-java / pki-ca / pki-core-debuginfo / etc");
}
