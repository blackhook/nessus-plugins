#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60663);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0217");

  script_name(english:"Scientific Linux Security Update : xmlsec1 on SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-0217 xmlsec1, mono, xml-security-c,
xml-security-1.3.0-1jpp.ep1.*: XMLDsig HMAC-based signatures spoofing
and authentication bypass

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1. An attacker
could use this flaw to create a specially crafted XML file that forges
an XML signature, allowing the attacker to bypass authentication that
is based on the XML Signature specification. (CVE-2009-0217)

After installing the updated packages, applications that use the XML
Security Library must be restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=201
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7495f20"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"xmlsec1-1.2.6-3.1")) flag++;
if (rpm_check(release:"SL4", reference:"xmlsec1-devel-1.2.6-3.1")) flag++;
if (rpm_check(release:"SL4", reference:"xmlsec1-openssl-1.2.6-3.1")) flag++;
if (rpm_check(release:"SL4", reference:"xmlsec1-openssl-devel-1.2.6-3.1")) flag++;

if (rpm_check(release:"SL5", reference:"xmlsec1-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-gnutls-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-gnutls-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-nss-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-nss-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-openssl-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"SL5", reference:"xmlsec1-openssl-devel-1.2.9-8.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
