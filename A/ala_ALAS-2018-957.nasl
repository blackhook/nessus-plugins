#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-957.
#

include("compat.inc");

if (description)
{
  script_id(106934);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_xref(name:"ALAS", value:"2018-957");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"Amazon Linux AMI : quagga (ALAS-2018-957)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Infinite loop issue triggered by invalid OPEN message allows
denial-of-service

An infinite loop vulnerability was discovered in Quagga. A BGP peer
could send specially crafted packets that would cause the daemon to
enter an infinite loop, denying service and consuming CPU until it is
restarted.(CVE-2018-5381)

Double free vulnerability in bgpd when processing certain forms of
UPDATE message allowing to crash or potentially execute arbitrary code

A double-free vulnerability was found in Quagga. A BGP peer could send
a specially crafted UPDATE message which would cause allocated blocks
of memory to be free()d more than once, potentially leading to a crash
or other issues.(CVE-2018-5379)

bgpd can overrun internal BGP code-to-string conversion tables
potentially allowing crash

A vulnerability was found in Quagga, in the log formatting code.
Specially crafted messages sent by BGP peers could cause Quagga to
read one element past the end of certain static arrays, causing
arbitrary binary data to appear in the logs or potentially, a
crash.(CVE-2018-5380)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-957.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update quagga' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"quagga-0.99.22.4-4.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-contrib-0.99.22.4-4.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-debuginfo-0.99.22.4-4.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-devel-0.99.22.4-4.17.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-debuginfo / quagga-devel");
}
