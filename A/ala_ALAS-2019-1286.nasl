#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1286.
#

include("compat.inc");

if (description)
{
  script_id(129013);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2016-3616", "CVE-2018-11212", "CVE-2018-11213", "CVE-2018-11214", "CVE-2018-11813", "CVE-2018-14498");
  script_xref(name:"ALAS", value:"2019-1286");

  script_name(english:"Amazon Linux AMI : libjpeg-turbo (ALAS-2019-1286)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The cjpeg utility in libjpeg allows remote attackers to cause a denial
of service (NULL pointer dereference and application crash) or execute
arbitrary code via a crafted file.(CVE-2016-3616)

libjpeg 9c has a large loop because read_pixel in rdtarga.c mishandles
EOF.(CVE-2018-11813)

An out-of-bounds read vulnerability has been discovered in
libjpeg-turbo when reading one row of pixels of a PPM file. An
attacker could use this flaw to crash the application and cause a
denial of service.(CVE-2018-11214)

An out-of-bound read vulnerability has been discovered in
libjpeg-turbo when reading one row of pixels of a PGM file. An
attacker could use this flaw to crash the application and cause a
denial of service.(CVE-2018-11213)

get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90 and MozJPEG
through 3.3.1 allows attackers to cause a denial of service
(heap-based buffer over-read and application crash) via a crafted
8-bit BMP in which one or more of the color indices is out of range
for the number of palette entries.(CVE-2018-14498)

A divide by zero vulnerability has been discovered in libjpeg-turbo in
alloc_sarray function of jmemmgr.c file. An attacker could use this
vulnerability to cause a denial of service via a crafted
file.(CVE-2018-11212)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1286.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libjpeg-turbo' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:turbojpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:turbojpeg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-debuginfo-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-devel-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-static-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-utils-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"turbojpeg-1.2.90-8.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"turbojpeg-devel-1.2.90-8.16.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo / libjpeg-turbo-debuginfo / libjpeg-turbo-devel / etc");
}
