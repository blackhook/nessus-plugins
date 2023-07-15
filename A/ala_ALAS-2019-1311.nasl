#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1311.
#

include("compat.inc");

if (description)
{
  script_id(130281);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098", "CVE-2019-9517");
  script_xref(name:"ALAS", value:"2019-1311");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2019-1311) (Internal Data Buffering)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability was found in Apache httpd, in mod_http2. Under certain
circumstances, HTTP/2 early pushes could lead to memory corruption,
causing a server to crash.(CVE-2019-10081)

A read-after-free vulnerability was discovered in Apache httpd, in
mod_http2. A specially crafted http/2 client session could cause the
server to read memory that was previously freed during connection
shutdown, potentially leading to a crash.(CVE-2019-10082)

A cross-site scripting vulnerability was found in Apache httpd,
affecting the mod_proxy error page. Under certain circumstances, a
crafted link could inject content into the HTML displayed in the error
page, potentially leading to client-side exploitation.(CVE-2019-10092)

A vulnerability was discovered in Apache httpd, in mod_remoteip. A
trusted proxy using the 'PROXY' protocol could send specially crafted
headers that can cause httpd to experience a stack buffer overflow or
NULL pointer dereference, leading to a crash or other potential
consequences.\n\nThis issue could only be exploited by configured
trusted intermediate proxy servers. HTTP clients such as browsers
could not exploit the vulnerability.(CVE-2019-10097)

A vulnerability was discovered in Apache httpd, in mod_rewrite.
Certain self-referential mod_rewrite rules could be fooled by encoded
newlines, causing them to redirect to an unexpected location. An
attacker could abuse this flaw in a phishing attack or as part of a
client-side attack on browsers.(CVE-2019-10098)

Some HTTP/2 implementations are vulnerable to unconstrained interal
data buffering, potentially leading to a denial of service. The
attacker opens the HTTP/2 window so the peer can send without
constraint; however, they leave the TCP window closed so the peer
cannot actually write (many of) the bytes on the wire. The attacker
then sends a stream of requests for a large response object. Depending
on how the servers queue the responses, this can consume excess
memory, CPU, or both.(CVE-2019-9517)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1311.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update httpd24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"ALA", reference:"httpd24-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_md-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.41-1.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.41-1.88.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd24 / httpd24-debuginfo / httpd24-devel / httpd24-manual / etc");
}
