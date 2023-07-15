#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1375.
#

include("compat.inc");

if (description)
{
  script_id(137098);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/09");

  script_cve_id("CVE-2018-20852");
  script_xref(name:"ALAS", value:"2020-1375");

  script_name(english:"Amazon Linux AMI : python27 (ALAS-2020-1375)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http.cookiejar.DefaultPolicy.domain_return_ok in Lib/http/cookiejar.py
in Python before 3.7.3 does not correctly validate the domain: it can
be tricked into sending existing cookies to the wrong server. An
attacker may abuse this flaw by using a server with a hostname that
has another valid hostname as a suffix (e.g., pythonicexample.com to
steal cookies for example.com). When a program uses
http.cookiejar.DefaultPolicy and tries to do an HTTP connection to an
attacker-controlled server, existing cookies can be leaked to the
attacker. This affects 2.x through 2.7.16, 3.x before 3.4.10, 3.5.x
before 3.5.7, 3.6.x before 3.6.9, and 3.7.x before
3.7.3.(CVE-2018-20852)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1375.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update python27' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");
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
if (rpm_check(release:"ALA", reference:"python27-2.7.18-1.137.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-debuginfo-2.7.18-1.137.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-devel-2.7.18-1.137.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libs-2.7.18-1.137.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-test-2.7.18-1.137.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tools-2.7.18-1.137.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / python27-libs / etc");
}
