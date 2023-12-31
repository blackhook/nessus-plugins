#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1428 and 
# Oracle Linux Security Advisory ELSA-2009-1428 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67921);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0217");
  script_bugtraq_id(35671);
  script_xref(name:"RHSA", value:"2009:1428");

  script_name(english:"Oracle Linux 4 / 5 : xmlsec1 (ELSA-2009-1428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1428 :

Updated xmlsec1 packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The XML Security Library is a C library based on libxml2 and OpenSSL.
It implements the XML Signature Syntax and Processing and XML
Encryption Syntax and Processing standards. HMAC is used for message
authentication using cryptographic hash functions. The HMAC algorithm
allows the hash output to be truncated (as documented in RFC 2104).

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1. An attacker
could use this flaw to create a specially crafted XML file that forges
an XML signature, allowing the attacker to bypass authentication that
is based on the XML Signature specification. (CVE-2009-0217)

Users of xmlsec1 should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, applications that use the XML Security Library must
be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001141.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xmlsec1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"xmlsec1-1.2.6-3.1")) flag++;
if (rpm_check(release:"EL4", reference:"xmlsec1-devel-1.2.6-3.1")) flag++;
if (rpm_check(release:"EL4", reference:"xmlsec1-openssl-1.2.6-3.1")) flag++;
if (rpm_check(release:"EL4", reference:"xmlsec1-openssl-devel-1.2.6-3.1")) flag++;

if (rpm_check(release:"EL5", reference:"xmlsec1-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-gnutls-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-gnutls-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-nss-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-nss-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-openssl-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"EL5", reference:"xmlsec1-openssl-devel-1.2.9-8.1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlsec1 / xmlsec1-devel / xmlsec1-gnutls / xmlsec1-gnutls-devel / etc");
}
