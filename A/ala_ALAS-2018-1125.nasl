#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1125.
#

include("compat.inc");

if (description)
{
  script_id(119688);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/02");

  script_cve_id("CVE-2018-16843", "CVE-2018-16844");
  script_xref(name:"ALAS", value:"2018-1125");

  script_name(english:"Amazon Linux AMI : nginx (ALAS-2018-1125)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the
implementation of HTTP/2 that can allow for excessive memory
consumption. This issue affects nginx compiled with the
ngx_http_v2_module (not compiled by default) if the 'http2' option of
the 'listen' directive is used in a configuration file.
(CVE-2018-16843)

nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the
implementation of HTTP/2 that can allow for excessive CPU usage. This
issue affects nginx compiled with the ngx_http_v2_module (not compiled
by default) if the 'http2' option of the 'listen' directive is used in
a configuration file. (CVE-2018-16844)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1125.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nginx' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-http-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"nginx-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-all-modules-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-debuginfo-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-geoip-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-image-filter-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-perl-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-xslt-filter-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-mail-1.14.1-2.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-stream-1.14.1-2.34.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-all-modules / nginx-debuginfo / nginx-mod-http-geoip / etc");
}
