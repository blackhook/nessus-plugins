#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1220.
#

include("compat.inc");

if (description)
{
  script_id(125603);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/13");

  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710");
  script_xref(name:"ALAS", value:"2019-1220");

  script_name(english:"Amazon Linux 2 : libxml2 (ALAS-2019-1220)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to leak
potentially sensitive information.(CVE-2015-8242)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to
crash.(CVE-2015-7500)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to leak
potentially sensitive information.(CVE-2015-8317)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to
crash.(CVE-2015-7497)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to
crash.(CVE-2015-7498)

A denial of service flaw was found in the way the libxml2 library
parsed certain XML files. An attacker could provide a specially
crafted XML file that, when parsed by an application using libxml2,
could cause that application to use an excessive amount of
memory.(CVE-2015-1819)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to
crash.(CVE-2015-7941)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to leak
potentially sensitive information.(CVE-2015-7499)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to leak
potentially sensitive information.(CVE-2015-8241)

A denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to use an
excessive amount of CPU.(CVE-2015-5312)

A heap-based buffer overflow flaw was found in the way libxml2 parsed
certain crafted XML input. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash causing a denial of
service.(CVE-2015-7942)

It was discovered that libxml2 could access out-of-bounds memory when
parsing unclosed HTML comments. A remote attacker could provide a
specially crafted XML file that, when processed by an application
linked against libxml2, could cause the application to disclose heap
memory contents.(CVE-2015-8710)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1220.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libxml2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");
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
if (rpm_check(release:"AL2", reference:"libxml2-2.9.1-6.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", reference:"libxml2-debuginfo-2.9.1-6.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", reference:"libxml2-devel-2.9.1-6.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", reference:"libxml2-python-2.9.1-6.amzn2.3.2")) flag++;
if (rpm_check(release:"AL2", reference:"libxml2-static-2.9.1-6.amzn2.3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / libxml2-python / etc");
}
