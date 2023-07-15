#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1326.
#

include("compat.inc");

if (description)
{
  script_id(132321);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2019-18218");
  script_xref(name:"ALAS", value:"2019-1326");

  script_name(english:"Amazon Linux AMI : file (ALAS-2019-1326)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"cdf_read_property_info in cdf.c in file through 5.37 does not restrict
the number of CDF_VECTOR elements, which allows a heap-based buffer
overflow (4-byte out-of-bounds write). (CVE-2019-18218)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1326.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update file' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18218");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"file-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-debuginfo-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-devel-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-libs-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"file-static-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-magic-5.37-8.48.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-magic-5.37-8.48.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-devel / file-libs / file-static / etc");
}
