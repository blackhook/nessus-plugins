#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1029.
#

include("compat.inc");

if (description)
{
  script_id(110446);
  script_version("1.3");
  script_cvs_date("Date: 2018/08/31 12:25:00");

  script_cve_id("CVE-2018-1000300", "CVE-2018-1000301");
  script_xref(name:"ALAS", value:"2018-1029");

  script_name(english:"Amazon Linux 2 : curl (ALAS-2018-1029)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Curl version curl 7.54.1 to and including curl 7.59.0 contains a
CWE-122: Heap-based Buffer Overflow vulnerability in denial of service
and more that can result in curl might overflow a heap based memory
buffer when closing down an FTP connection with very long server
command replies.(CVE-2018-1000300)

Curl version curl 7.20.0 to and including curl 7.59.0 contains a
CWE-126: Buffer Over-read vulnerability in denial of service that can
result in curl can be tricked into reading data beyond the end of a
heap based buffer used to store downloaded RTSP
content.(CVE-2018-1000301)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1029.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"curl-7.55.1-12.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"curl-debuginfo-7.55.1-12.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libcurl-7.55.1-12.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libcurl-devel-7.55.1-12.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
