#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-958.
#

include("compat.inc");

if (description)
{
  script_id(106935);
  script_version("3.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");
  script_xref(name:"ALAS", value:"2018-958");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2018-958)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Heap-based buffer overflow in mspack/lzxd.c :

mspack/lzxd.c in libmspack 0.5alpha, as used in ClamAV 0.99.2, allows
remote attackers to cause a denial of service (heap-based buffer
overflow and application crash) or possibly have unspecified other
impact via a crafted CHM file.(CVE-2017-6419)

The wwunpack function in libclamav/wwunpack.c in ClamAV 0.99.2 allows
remote attackers to cause a denial of service (use-after-free) via a
crafted PE file with WWPack compression.(CVE-2017-6420)

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device. The vulnerability is due to
improper input validation checking mechanisms when handling Portable
Document Format (.pdf) files sent to an affected device. An
unauthenticated, remote attacker could exploit this vulnerability by
sending a crafted .pdf file to an affected device. This action could
cause a handle_pdfname (in pdf.c) buffer overflow when ClamAV scans
the malicious file, allowing the attacker to cause a DoS condition or
potentially execute arbitrary code. (CVE-2017-12376)

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to improper input validation checking mechanisms
of .tar (Tape Archive) files sent to an affected device. A successful
exploit could cause a checksum buffer over-read condition when ClamAV
scans the malicious .tar file, potentially allowing the attacker to
cause a DoS condition on the affected device.(CVE-2017-12378)

The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to a lack of input validation checking mechanisms
during certain mail parsing functions (the rfc2047 function in
mbox.c). An unauthenticated, remote attacker could exploit this
vulnerability by sending a crafted email to the affected device. This
action could cause a buffer overflow condition when ClamAV scans the
malicious email, allowing the attacker to potentially cause a DoS
condition on an affected device.(CVE-2017-12375)

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device. The vulnerability is due to
improper input validation checking mechanisms in the message parsing
function on an affected system. An unauthenticated, remote attacker
could exploit this vulnerability by sending a crafted email to the
affected device. This action could cause a messageAddArgument (in
message.c) buffer overflow condition when ClamAV scans the malicious
email, allowing the attacker to potentially cause a DoS condition or
execute arbitrary code on an affected device.(CVE-2017-12379)

libclamav/message.c in ClamAV 0.99.2 allows remote attackers to cause
a denial of service (out-of-bounds read) via a crafted e-mail
message.(CVE-2017-6418)

The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to a lack of input validation checking mechanisms
during certain mail parsing operations (mbox.c operations on bounce
messages). If successfully exploited, the ClamAV software could allow
a variable pointing to the mail body which could cause a used after
being free (use-after-free) instance which may lead to a disruption of
services on an affected device to include a denial of service
condition.(CVE-2017-12374)

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device. The vulnerability is due to
improper input validation checking mechanisms in mew packet files sent
to an affected device. A successful exploit could cause a heap-based
buffer over-read condition in mew.c when ClamAV scans the malicious
file, allowing the attacker to cause a DoS condition or potentially
execute arbitrary code on the affected device.(CVE-2017-12377)

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. The
vulnerability is due to improper input validation checking mechanisms
in mbox.c during certain mail parsing functions of the ClamAV
software. An unauthenticated, remote attacker could exploit this
vulnerability by sending a crafted email to the affected device. An
exploit could trigger a NULL pointer dereference condition when ClamAV
scans the malicious email, which may result in a DoS
condition.(CVE-2017-12380)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-958.html"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"clamav-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-empty-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-db-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-debuginfo-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-devel-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-filesystem-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-lib-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-sysvinit-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-scanner-sysvinit-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-server-sysvinit-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-update-0.99.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamd-0.99.3-1.28.amzn1")) flag++;

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
