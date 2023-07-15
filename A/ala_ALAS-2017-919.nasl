#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-919.
#

include("compat.inc");

if (description)
{
  script_id(104393);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-1000254");
  script_xref(name:"ALAS", value:"2017-919");

  script_name(english:"Amazon Linux AMI : curl (ALAS-2017-919)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FTP PWD response parser out of bounds read

libcurl may read outside of a heap allocated buffer when doing FTP.
When libcurl connects to an FTP server and successfully logs in
(anonymous or not), it asks the server for the current directory with
the `PWD` command. The server then responds with a 257 response
containing the path, inside double quotes. The returned path name is
then kept by libcurl for subsequent uses. Due to a flaw in the string
parser for this directory name, a directory name passed like this but
without a closing double quote would lead to libcurl not adding a
trailing NUL byte to the buffer holding the name. When libcurl would
then later access the string, it could read beyond the allocated heap
buffer and crash or wrongly access data beyond the buffer, thinking it
was part of the path. A malicious server could abuse this fact and
effectively prevent libcurl-based clients to work with it - the PWD
command is always issued on new FTP connections and the mistake has a
high chance of causing a segfault. The simple fact that this has issue
remained undiscovered for this long could suggest that malformed PWD
responses are rare in benign servers. We are not aware of any exploit
of this flaw. This bug was introduced in commit
[415d2e7cb7](https://github.com/curl/curl/commit/415d2e7cb7), March
2005. In libcurl version 7.56.0, the parser always zero terminates the
string but also rejects it if not terminated properly with a final
double quote. (CVE-2017-1000254 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-919.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");
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
if (rpm_check(release:"ALA", reference:"curl-7.53.1-11.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"curl-debuginfo-7.53.1-11.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-7.53.1-11.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcurl-devel-7.53.1-11.78.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
