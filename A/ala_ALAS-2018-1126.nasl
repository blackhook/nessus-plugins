#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1126.
#

include("compat.inc");

if (description)
{
  script_id(121359);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-1050", "CVE-2018-10858", "CVE-2018-1139");
  script_xref(name:"ALAS", value:"2018-1126");

  script_name(english:"Amazon Linux AMI : samba (ALAS-2018-1126)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in Samba RPC external
printer service. An attacker could use this flaw to cause the printer
spooler service to crash. (CVE-2018-1050)

A heap-buffer overflow was found in the way samba clients processed
extra long filename in a directory listing. A malicious samba server
could use this flaw to cause arbitrary code execution on a samba
client. (CVE-2018-10858)

A flaw was found in the way samba allowed the use of weak NTLMv1
authentication even when NTLMv1 was explicitly disabled. A
man-in-the-middle attacker could use this flaw to read the credential
and other details passed between the samba server and client.
(CVE-2018-1139)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1126.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update samba' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"ctdb-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ctdb-tests-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-devel-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-devel-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-libs-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-libs-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-tools-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-debuginfo-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-devel-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-krb5-printing-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-libs-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-pidl-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-python-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-python-test-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-libs-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-clients-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-krb5-locator-4.8.3-4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-modules-4.8.3-4.amzn1")) flag++;

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
