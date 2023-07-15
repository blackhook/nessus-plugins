#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-784.
#

include("compat.inc");

if (description)
{
  script_id(96395);
  script_version("3.7");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2013-5653", "CVE-2016-7977", "CVE-2016-7979", "CVE-2016-8602");
  script_xref(name:"ALAS", value:"2017-784");

  script_name(english:"Amazon Linux AMI : ghostscript (ALAS-2017-784)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the ghostscript functions getenv, filenameforall and
.libfile did not honor the -dSAFER option, usually used when
processing untrusted documents, leading to information disclosure. A
specially crafted postscript document could read environment variable,
list directory and retrieve file content respectively, from the
target. (CVE-2013-5653 , CVE-2016-7977)

It was found that the ghostscript function .initialize_dsc_parser did
not validate its parameter before using it, allowing a type confusion
flaw. A specially crafted postscript document could cause a crash code
execution in the context of the gs process. (CVE-2016-7979)

It was found that ghostscript did not sufficiently check the validity
of parameters given to the .sethalftone5 function. A specially crafted
postscript document could cause a crash, or execute arbitrary code in
the context of the gs process. (CVE-2016-8602)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-784.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ghostscript' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"ghostscript-8.70-21.1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-debuginfo-8.70-21.1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-devel-8.70-21.1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ghostscript-doc-8.70-21.1.24.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
}
