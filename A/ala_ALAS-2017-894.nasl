#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-894.
#

include("compat.inc");

if (description)
{
  script_id(103228);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-7529");
  script_xref(name:"ALAS", value:"2017-894");

  script_name(english:"Amazon Linux AMI : nginx (ALAS-2017-894)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw within the processing of ranged HTTP requests has been
discovered in the range filter module of nginx. A remote attacker
could possibly exploit this flaw to disclose parts of the cache file
header, or, if used in combination with third party modules, disclose
potentially sensitive memory by sending specially crafted HTTP
requests. (CVE-2017-7529)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-894.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nginx' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");
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
if (rpm_check(release:"ALA", reference:"nginx-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-all-modules-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-debuginfo-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-geoip-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-image-filter-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-perl-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-http-xslt-filter-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-mail-1.12.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nginx-mod-stream-1.12.1-1.32.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-all-modules / nginx-debuginfo / nginx-mod-http-geoip / etc");
}
