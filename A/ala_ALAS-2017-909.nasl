#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-909.
#

include("compat.inc");

if (description)
{
  script_id(103822);
  script_version("3.5");
  script_cvs_date("Date: 2018/10/01 10:24:12");

  script_cve_id("CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163");
  script_xref(name:"ALAS", value:"2017-909");

  script_name(english:"Amazon Linux AMI : samba (ALAS-2017-909)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Server memory information leak over SMB1 :

An information leak flaw was found in the way SMB1 protocol was
implemented by Samba. A malicious client could use this flaw to dump
server memory contents to a file on the samba share or to a shared
printer, though the exact area of server memory cannot be controlled
by the attacker. (CVE-2017-12163)

SMB2 connections don't keep encryption across DFS redirects

A flaw was found in the way samba client used encryption with the max
protocol set as SMB3. The connection could lose the requirement for
signing and encrypting to any DFS redirects, allowing an attacker to
read or alter the contents of the connection via a man-in-the-middle
attack. (CVE-2017-12151)

Some code path don't enforce smb signing, when they should

It was found that samba did not enforce 'SMB signing' when certain
configuration options were enabled. A remote attacker could launch a
man-in-the-middle attack and retrieve information in plain-text.
(CVE-2017-12150)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-909.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update samba' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"ctdb-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ctdb-tests-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-devel-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-devel-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-libs-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-libs-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-tools-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-debuginfo-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-devel-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-krb5-printing-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-libs-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-pidl-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-python-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-libs-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-clients-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-krb5-locator-4.6.2-11.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-modules-4.6.2-11.36.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
