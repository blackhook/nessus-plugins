#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1150.
#

include("compat.inc");

if (description)
{
  script_id(121363);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2016-9396", "CVE-2017-1000050");
  script_xref(name:"ALAS", value:"2019-1150");

  script_name(english:"Amazon Linux 2 : jasper (ALAS-2019-1150)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The JPC_NOMINALGAIN function in jpc/jpc_t1cod.c in JasPer through
2.0.12 allows remote attackers to cause a denial of service
(JPC_COX_RFT assertion failure) via unspecified
vectors.(CVE-2016-9396)

JasPer 2.0.12 is vulnerable to a NULL pointer exception in the
function jp2_encode which failed to check to see if the image
contained at least one component resulting in a
denial-of-service.(CVE-2017-1000050)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1150.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update jasper' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/23");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"jasper-1.900.1-33.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"jasper-debuginfo-1.900.1-33.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"jasper-devel-1.900.1-33.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"jasper-libs-1.900.1-33.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"jasper-utils-1.900.1-33.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-devel / jasper-libs / etc");
}
