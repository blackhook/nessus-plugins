#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1129.
#

include("compat.inc");

if (description)
{
  script_id(119784);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2018-5729", "CVE-2018-5730");
  script_xref(name:"ALAS", value:"2018-1129");

  script_name(english:"Amazon Linux 2 : krb5 (ALAS-2018-1129)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MIT krb5 1.6 or later allows an authenticated kadmin with permission
to add principals to an LDAP Kerberos database to circumvent a DN
containership check by supplying both a 'linkdn' and 'containerdn'
database argument, or by supplying a DN string which is a left
extension of a container DN string but is not hierarchically within
the container DN.(CVE-2018-5730)

MIT krb5 1.6 or later allows an authenticated kadmin with permission
to add principals to an LDAP Kerberos database to cause a denial of
service (NULL pointer dereference) or bypass a DN container check by
supplying tagged data that is internal to the database
module.(CVE-2018-5729)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1129.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update krb5' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libkadm5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"krb5-debuginfo-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-devel-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-libs-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-pkinit-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-server-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-server-ldap-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"krb5-workstation-1.15.1-20.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libkadm5-1.15.1-20.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-debuginfo / krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
