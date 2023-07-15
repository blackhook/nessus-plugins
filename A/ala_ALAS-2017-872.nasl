#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-872.
#

include("compat.inc");

if (description)
{
  script_id(102546);
  script_version("3.4");
  script_cvs_date("Date: 2018/08/31 12:25:00");

  script_cve_id("CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");
  script_xref(name:"ALAS", value:"2017-872");

  script_name(english:"Amazon Linux AMI : graphite2 (ALAS-2017-872)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerabilities in the Graphite 2 library (MFSA 2017-16)

A heap-based buffer overflow flaw related to 'lz4::decompress' has
been reported in graphite2. An attacker could exploit this issue to
cause a crash or, possibly, execute arbitrary code. (CVE-2017-7778)

Heap-buffer-overflow write 'lz4::decompress' (src/Decompressor)

A heap-based buffer overflow flaw related to 'lz4::decompress'
(src/Decompressor) has been reported in graphite2. An attacker could
exploit this issue to cause a crash or, possibly, execute arbitrary
code. (CVE-2017-7772)(CVE-2017-7773)

Out of bounds read in 'graphite2::Pass::readPass' :

An out of bounds read flaw related to 'graphite2::Pass::readPass' has
been reported in graphite2. An attacker could possibly exploit this
flaw to disclose potentially sensitive memory or cause an application
crash. (CVE-2017-7771)

Heap-buffer-overflow read 'graphite2::Silf::getClassGlyph'

An out of bounds read flaw related to 'graphite2::Silf::getClassGlyph'
has been reported in graphite2. An attacker could possibly exploit
this flaw to disclose potentially sensitive memory or cause an
application crash.(CVE-2017-7776)

Use of uninitialized memory
'graphite2::GlyphCache::Loader::read_glyph' :

The use of uninitialized memory related to
'graphite2::GlyphCache::Loader::read_glyph' has been reported in
graphite2. An attacker could possibly exploit this flaw to negatively
impact the execution of an application using graphite2 in unknown
ways. (CVE-2017-7777)

Out of bounds read 'graphite2::Silf::readGraphite'

An out of bounds read flaw related to 'graphite2::Silf::readGraphite'
has been reported in graphite2. An attacker could possibly exploit
this flaw to disclose potentially sensitive memory or cause an
application crash. (CVE-2017-7774)

Assertion error 'size() > n' :

An assertion error has been reported in graphite2. An attacker could
possibly exploit this flaw to cause an application crash.
(CVE-2017-7775)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-872.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update graphite2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphite2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphite2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"graphite2-1.3.10-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphite2-debuginfo-1.3.10-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphite2-devel-1.3.10-1.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphite2 / graphite2-debuginfo / graphite2-devel");
}
