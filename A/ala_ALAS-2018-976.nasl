#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-976.
#

include("compat.inc");

if (description)
{
  script_id(108601);
  script_version("1.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2012-6706", "CVE-2017-11423", "CVE-2017-6419", "CVE-2018-0202", "CVE-2018-1000085");
  script_xref(name:"ALAS", value:"2018-976");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2018-976)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Heap-based buffer overflow in mspack/lzxd.c

mspack/lzxd.c in libmspack 0.5alpha, as used in ClamAV 0.99.2, allows
remote attackers to cause a denial of service (heap-based buffer
overflow and application crash) or possibly have unspecified other
impact via a crafted CHM file. (CVE-2017-6419)

Out-of-bounds access in the PDF parser (CVE-2018-0202)

A VMSF_DELTA memory corruption was discovered in unrar before 5.5.5,
as used in Sophos Anti-Virus Threat Detection Engine before 3.37.2 and
other products, that can lead to arbitrary code execution. An integer
overflow can be caused in DataSize+CurChannel. The result is a
negative value of the 'DestPos' variable, which allows the attacker to
write out of bounds when setting Mem[DestPos]. (CVE-2012-6706)

ClamAV version version 0.99.3 contains a Out of bounds heap memory
read vulnerability in XAR parser, function xar_hash_check() that can
result in Leaking of memory, may help in developing exploit chains..
This attack appear to be exploitable via The victim must scan a
crafted XAR file. (CVE-2018-1000085)

Stack-based buffer over-read in cabd_read_string function

The cabd_read_string function in mspack/cabd.c in libmspack 0.5alpha,
as used in ClamAV 0.99.2 and other products, allows remote attackers
to cause a denial of service (stack-based buffer over-read and
application crash) via a crafted CAB file. (CVE-2017-11423)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-976.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update clamav' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data-empty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-scanner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-scanner-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-server-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"clamav-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-empty-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-db-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-debuginfo-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-devel-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-filesystem-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-lib-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-sysvinit-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-sysvinit-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-sysvinit-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-update-0.99.4-1.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamd-0.99.4-1.29.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-data-empty / clamav-db / etc");
}
