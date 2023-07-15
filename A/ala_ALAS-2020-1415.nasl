#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1415.
#

include('compat.inc');

if (description)
{
  script_id(139549);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2015-8035",
    "CVE-2016-5131",
    "CVE-2017-15412",
    "CVE-2017-18258",
    "CVE-2018-14404",
    "CVE-2018-14567"
  );
  script_xref(name:"ALAS", value:"2020-1415");

  script_name(english:"Amazon Linux AMI : libxml2 (ALAS-2020-1415)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A NULL pointer dereference vulnerability exists in the
xpath.c:xmlXPathCompOpEval() function of libxml2 through 2.9.8 when
parsing an invalid XPath expression in the XPATH_OP_AND or XPATH_OP_OR
case. Applications processing untrusted XSL format inputs with the use
of the libxml2 library may be vulnerable to a denial of service attack
due to a crash of the application. A NULL pointer dereference
vulnerability exists in the xpath.c:xmlXPathCompOpEval() function of
libxml2 when parsing invalid XPath expression. Applications processing
untrusted XSL format inputs with the use of libxml2 library may be
vulnerable to denial of service attack due to crash of the
application. (CVE-2018-14404)

Use after free in libxml2 before 2.9.5, as used in Google Chrome prior
to 63.0.3239.84 and other products, allowed a remote attacker to
potentially exploit heap corruption via a crafted HTML page. A
use-after-free flaw was found in the libxml2 library. An attacker
could use this flaw to cause an application linked against libxml2 to
crash when parsing a specially crafted XML file. (CVE-2017-15412)

The xz_decomp function in xzlib.c in libxml2 2.9.1 does not properly
detect compression errors, which allows context-dependent attackers to
cause a denial of service (process hang) via crafted XML data. A
denial of service flaw was found in libxml2. A remote attacker could
provide a specially crafted XML or HTML file that, when processed by
an application using libxml2, would cause that application to crash.
(CVE-2015-8035)

libxml2 2.9.8, if --with-lzma is used, allows remote attackers to
cause a denial of service (infinite loop) via a crafted XML file that
triggers LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint, a different
vulnerability than CVE-2015-8035 and CVE-2018-9251 . (CVE-2018-14567)

The xz_head function in xzlib.c in libxml2 before 2.9.6 allows remote
attackers to cause a denial of service (memory consumption) via a
crafted LZMA file, because the decoder functionality does not restrict
memory usage to what is required for a legitimate file.
(CVE-2017-18258)

Use-after-free vulnerability in libxml2 through 2.9.4, as used in
Google Chrome before 52.0.2743.82, allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
vectors related to the XPointer range-to function. (CVE-2016-5131)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1415.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libxml2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"libxml2-2.9.1-6.4.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-debuginfo-2.9.1-6.4.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-devel-2.9.1-6.4.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python26-2.9.1-6.4.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-python27-2.9.1-6.4.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxml2-static-2.9.1-6.4.40.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / libxml2-python26 / etc");
}
