#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-70.
#

include("compat.inc");

if (description)
{
  script_id(69677);
  script_version("1.5");
  script_cvs_date("Date: 2018/04/18 15:09:34");

  script_cve_id("CVE-2012-0250");
  script_xref(name:"ALAS", value:"2012-70");

  script_name(english:"Amazon Linux AMI : quagga (ALAS-2012-70)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the OSPFv2 implementation in ospfd in Quagga before
0.99.20.1 allows remote attackers to cause a denial of service (daemon
crash) via a Link State Update (aka LS Update) packet containing a
network-LSA link-state advertisement for which the data-structure
length is smaller than the value in the Length header field."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-70.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update quagga' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"quagga-0.99.20.1-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-contrib-0.99.20.1-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-debuginfo-0.99.20.1-1.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"quagga-devel-0.99.20.1-1.4.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-debuginfo / quagga-devel");
}
