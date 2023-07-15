#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-117.
#

include("compat.inc");

if (description)
{
  script_id(69607);
  script_version("1.5");
  script_cvs_date("Date: 2018/04/18 15:09:34");

  script_cve_id("CVE-2012-2668");
  script_xref(name:"ALAS", value:"2012-117");
  script_xref(name:"RHSA", value:"2012:1151");

  script_name(english:"Amazon Linux AMI : openldap (ALAS-2012-117)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
settings. This resulted in the default cipher suite always being used,
which could lead to weaker than expected ciphers being accepted during
Transport Layer Security (TLS) negotiation with OpenLDAP clients.
(CVE-2012-2668)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-117.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openldap' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"openldap-2.4.23-26.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-clients-2.4.23-26.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-debuginfo-2.4.23-26.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-devel-2.4.23-26.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-servers-2.4.23-26.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openldap-servers-sql-2.4.23-26.16.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-debuginfo / openldap-devel / etc");
}
