#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1155.
#

include("compat.inc");

if (description)
{
  script_id(121368);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-11763");
  script_xref(name:"ALAS", value:"2019-1155");

  script_name(english:"Amazon Linux 2 : httpd (ALAS-2019-1155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Apache HTTP Server 2.4.17 to 2.4.34, by sending continuous, large
SETTINGS frames a client can occupy a connection, server thread and
CPU time without any connection timeout coming to effect. This affects
only HTTP/2 connections. A possible mitigation is to not enable the h2
protocol.(CVE-2018-11763)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1155.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"httpd-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-debuginfo-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-devel-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-filesystem-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-manual-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"httpd-tools-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_ldap-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_md-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_proxy_html-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_session-2.4.37-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"mod_ssl-2.4.37-1.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-filesystem / etc");
}
