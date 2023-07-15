#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-911.
#

include("compat.inc");

if (description)
{
  script_id(103824);
  script_version("3.4");
  script_cvs_date("Date: 2018/08/31 12:25:00");

  script_cve_id("CVE-2017-7805");
  script_xref(name:"ALAS", value:"2017-911");

  script_name(english:"Amazon Linux AMI : nss (ALAS-2017-911)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Potential use-after-free in TLS 1.2 server when verifying client
authentication :

A use-after-free flaw was found in the TLS 1.2 implementation in the
NSS library when client authentication was used. A malicious client
could use this flaw to cause an application compiled against NSS to
crash or, potentially, execute arbitrary code with the permission of
the user running the application. (CVE-2017-7805)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-911.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nss' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/12");
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
if (rpm_check(release:"ALA", reference:"nss-3.28.4-12.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.28.4-12.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.28.4-12.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.28.4-12.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.28.4-12.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.28.4-12.80.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
