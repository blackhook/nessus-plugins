#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1004.
#

include("compat.inc");

if (description)
{
  script_id(109555);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1302", "CVE-2018-1303", "CVE-2018-1312");
  script_xref(name:"ALAS", value:"2018-1004");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2018-1004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Use-after-free on HTTP/2 stream shutdown

When an HTTP/2 stream was destroyed after being handled, the Apache
HTTP Server prior to version 2.4.30 could have written a NULL pointer
potentially to an already freed memory. The memory pools maintained by
the server make this vulnerability hard to trigger in usual
configurations, the reporter and the team could not reproduce it
outside debug builds, so it is classified as low risk. (CVE-2018-1302)

Bypass with a trailing newline in the file name

In Apache httpd 2.4.0 to 2.4.29, the expression specified in
<FilesMatch> could match '$' to a newline character in a malicious
filename, rather than matching only the end of the filename. This
could be exploited in environments where uploads of some files are are
externally blocked, but only by matching the trailing portion of the
filename. (CVE-2017-15715)

Out of bounds read in mod_cache_socache can allow a remote attacker to
cause a denial of service

A specially crafted HTTP request header could have crashed the Apache
HTTP Server prior to version 2.4.30 due to an out of bound read while
preparing data to be cached in shared memory. It could be used as a
Denial of Service attack against users of mod_cache_socache. The
vulnerability is considered as low risk since mod_cache_socache is not
widely used, mod_cache_disk is not concerned by this vulnerability.
(CVE-2018-1303)

Improper handling of headers in mod_session can allow a remote user to
modify session data for CGI applications

It has been discovered that the mod_session module of Apache HTTP
Server (httpd), through version 2.4.29, has an improper input
validation flaw in the way it handles HTTP session headers in some
configurations. A remote attacker may influence their content by using
a 'Session' header. (CVE-2018-1283)

Out of bound write in mod_authnz_ldap when using too small
Accept-Language values

In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to
2.4.29, mod_authnz_ldap, if configured with AuthLDAPCharsetConfig,
uses the Accept-Language header value to lookup the right charset
encoding when verifying the user's credentials. If the header value is
not present in the charset conversion table, a fallback mechanism is
used to truncate it to a two characters value to allow a quick retry
(for example, 'en-US' is truncated to 'en'). A header value of less
than two characters forces an out of bound write of one NUL byte to a
memory location that is not part of the string. In the worst case,
quite unlikely, the process would crash which could be used as a
Denial of Service attack. In the more likely case, this memory is
already reserved for future use and the issue has no effect at all.
(CVE-2017-15710)

Out of bound access after failure in reading the HTTP request

A specially crafted request could have crashed the Apache HTTP Server
prior to version 2.4.30, due to an out of bound access after a size
limit is reached by reading the HTTP header. This vulnerability is
considered very hard if not impossible to trigger in non-debug mode
(both log and build level), so it is classified as low risk for common
server usage. (CVE-2018-1301)

Weak Digest auth nonce generation in mod_auth_digest

In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest
authentication challenge, the nonce sent to prevent reply attacks was
not correctly generated using a pseudo-random seed. In a cluster of
servers using a common Digest authentication configuration, HTTP
requests could be replayed across servers by an attacker without
detection. (CVE-2018-1312)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1004.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"httpd24-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_md-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.33-2.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.33-2.78.amzn1")) flag++;

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
