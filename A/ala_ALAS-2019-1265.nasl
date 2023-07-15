#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1265.
#

include("compat.inc");

if (description)
{
  script_id(127818);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/02");

  script_cve_id("CVE-2018-19052");
  script_xref(name:"ALAS", value:"2019-1265");

  script_name(english:"Amazon Linux AMI : lighttpd (ALAS-2019-1265)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in mod_alias_physical_handler in mod_alias.c
in lighttpd before 1.4.50. There is potential ../ path traversal of a
single directory above an alias target, with a specific mod_alias
configuration where the matched alias lacks a trailing '/' character,
but the alias target filesystem path does have a trailing '/'
character.(CVE-2018-19052)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1265.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update lighttpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_authn_pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");
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
if (rpm_check(release:"ALA", reference:"lighttpd-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-debuginfo-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-fastcgi-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_authn_gssapi-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_authn_mysql-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_authn_pam-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_geoip-1.4.53-1.36.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"lighttpd-mod_mysql_vhost-1.4.53-1.36.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-fastcgi / etc");
}
