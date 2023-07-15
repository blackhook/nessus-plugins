#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1151.
#

include("compat.inc");

if (description)
{
  script_id(122035);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2018-0500", "CVE-2018-20483");
  script_xref(name:"ALAS", value:"2019-1151");

  script_name(english:"Amazon Linux AMI : curl (ALAS-2019-1151)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"set_file_metadata in xattr.c in GNU Wget stores a file's origin URL in
the user.xdg.origin.url metadata attribute of the extended attributes
of the downloaded file, which allows local users to obtain sensitive
information (e.g., credentials contained in the URL) by reading this
attribute, as demonstrated by getfattr. This also applies to Referer
information in the user.xdg.referrer.url metadata attribute. According
to 2016-07-22 in the Wget ChangeLog, user.xdg.origin.url was partially
based on the behavior of fwrite_xattr in tool_xattr.c in
curl.(CVE-2018-20483)

A heap-based buffer overflow has been found in the
Curl_smtp_escape_eob() function of curl. An attacker could exploit
this by convincing a user to use curl to upload data over SMTP with a
reduced buffer to cause a crash or corrupt memory.(CVE-2018-0500)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1151.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");
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
if (rpm_check(release:"ALA", reference:"curl-7.61.1-7.91.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"curl-debuginfo-7.61.1-7.91.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-7.61.1-7.91.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-devel-7.61.1-7.91.amzn1")) flag++;

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
