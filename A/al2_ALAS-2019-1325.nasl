#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1325.
#

include("compat.inc");

if (description)
{
  script_id(130222);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2017-14503", "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2019-1000019", "CVE-2019-1000020");
  script_xref(name:"ALAS", value:"2019-1325");

  script_name(english:"Amazon Linux 2 : libarchive (ALAS-2019-1325)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libarchive 3.3.2 suffers from an out-of-bounds read within
lha_read_data_none() in archive_read_support_format_lha.c when
extracting a specially crafted lha archive, related to
lha_crc16.(CVE-2017-14503)

libarchive version commit 416694915449219d505531b1096384f3237dd6cc
onwards (release v3.1.0 onwards) contains a CWE-415: Double Free
vulnerability in RAR decoder -
libarchive/archive_read_support_format_rar.c, parse_codes(),
realloc(rar->lzss.window, new_size) with new_size = 0 that can result
in Crash/DoS. This attack appear to be exploitable via the victim must
open a specially crafted RAR archive.(CVE-2018-1000877)

libarchive version commit 416694915449219d505531b1096384f3237dd6cc
onwards (release v3.1.0 onwards) contains a CWE-416: Use After Free
vulnerability in RAR decoder -
libarchive/archive_read_support_format_rar.c that can result in
Crash/DoS - it is unknown if RCE is possible. This attack appear to be
exploitable via the victim must open a specially crafted RAR
archive.(CVE-2018-1000878)

libarchive version commit bf9aec176c6748f0ee7a678c5f9f9555b9a757c1
onwards (release v3.0.2 onwards) contains a CWE-125: Out-of-bounds
Read vulnerability in 7zip decompression,
archive_read_support_format_7zip.c, header_bytes() that can result in
a crash (denial of service). This attack appears to be exploitable via
the victim opening a specially crafted 7zip file.(CVE-2019-1000019)

libarchive version commit 5a98dcf8a86364b3c2c469c85b93647dfb139961
onwards (version v2.8.0 onwards) contains a CWE-835: Loop with
Unreachable Exit Condition ('Infinite Loop') vulnerability in ISO9660
parser, archive_read_support_format_iso9660.c,
read_CE()/parse_rockridge() that can result in DoS by infinite loop.
This attack appears to be exploitable via the victim opening a
specially crafted ISO9660 file.(CVE-2019-1000020)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1325.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libarchive' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"bsdcpio-3.1.2-12.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"bsdtar-3.1.2-12.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libarchive-3.1.2-12.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libarchive-debuginfo-3.1.2-12.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libarchive-devel-3.1.2-12.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdcpio / bsdtar / libarchive / libarchive-debuginfo / etc");
}
