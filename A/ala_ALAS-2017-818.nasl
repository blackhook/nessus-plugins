#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-818.
#

include("compat.inc");

if (description)
{
  script_id(99531);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/28");

  script_cve_id("CVE-2017-6188");
  script_xref(name:"ALAS", value:"2017-818");

  script_name(english:"Amazon Linux AMI : munin (ALAS-2017-818)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Munin before 2.999.6 has a local file write vulnerability when CGI
graphs are enabled. Setting multiple upper_limit GET parameters allows
overwriting any file accessible to the www-data user. (CVE-2017-6188)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-818.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update munin' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-async");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-java-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-netip-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:munin-ruby-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"munin-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-async-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-cgi-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-common-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-java-plugins-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-netip-plugins-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-nginx-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-node-2.0.30-5.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"munin-ruby-plugins-2.0.30-5.38.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "munin / munin-async / munin-cgi / munin-common / munin-java-plugins / etc");
}
