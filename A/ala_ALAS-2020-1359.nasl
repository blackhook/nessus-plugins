#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1359.
#

include("compat.inc");

if (description)
{
  script_id(135935);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/28");

  script_cve_id("CVE-2018-12121", "CVE-2018-7159", "CVE-2019-15605");
  script_xref(name:"ALAS", value:"2020-1359");

  script_name(english:"Amazon Linux AMI : http-parser (ALAS-2020-1359)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the Node.js code where a specially crafted HTTP(s)
request sent to a Node.js server failed to properly process the
HTTP(s) headers, resulting in a request smuggling attack. An attacker
can use this flaw to alter a request sent as an authenticated user if
the Node.js server is deployed behind a proxy server that reuses
connections. (CVE-2019-15605)

Node.js: All versions prior to Node.js 6.15.0, 8.14.0, 10.14.0 and
11.3.0: Denial of Service with large HTTP headers: By using a
combination of many requests with maximum sized headers (almost 80 KB
per connection), and carefully timed completion of the headers, it is
possible to cause the HTTP server to abort from heap allocation
failure. Attack potential is mitigated by the use of a load balancer
or other proxy layer. (CVE-2018-12121)

It was found that the http module from Node.js could accept incorrect
Content-Length values, containing spaces within the value, in HTTP
headers. A specially crafted client could use this flaw to possibly
confuse the script, causing unspecified behavior. (CVE-2018-7159)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1359.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update http-parser' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:http-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:http-parser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:http-parser-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"http-parser-2.9.3-1.2.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"http-parser-debuginfo-2.9.3-1.2.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"http-parser-devel-2.9.3-1.2.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "http-parser / http-parser-debuginfo / http-parser-devel");
}
