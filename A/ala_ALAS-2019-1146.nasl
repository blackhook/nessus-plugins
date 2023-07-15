#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1146.
#

include("compat.inc");

if (description)
{
  script_id(121131);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-15378");
  script_xref(name:"ALAS", value:"2019-1146");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2019-1146)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in kwajd_read_headers in mspack/kwajd.c in
libmspack before 0.7alpha. Bad KWAJ file header extensions could cause
a one or two byte overwrite.(CVE-2018-14681)

An issue was discovered in mspack/chmd.c in libmspack before 0.7alpha.
There is an off-by-one error in the TOLOWER() macro for CHM
decompression.(CVE-2018-14682)

An issue was discovered in mspack/chmd.c in libmspack before 0.7alpha.
It does not reject blank CHM filenames.(CVE-2018-14680)

A vulnerability in ClamAV versions prior to 0.100.2 could allow an
attacker to cause a denial of service (DoS) condition. The
vulnerability is due to an error related to the MEW unpacker within
the 'unmew11()' function (libclamav/mew.c), which can be exploited to
trigger an invalid read memory access via a specially crafted EXE
file.(CVE-2018-15378)

An issue was discovered in mspack/chmd.c in libmspack before 0.7alpha.
There is an off-by-one error in the CHM PMGI/PMGL chunk number
validity checks, which could lead to denial of service (uninitialized
data dereference and application crash).(CVE-2018-14679)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1146.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update clamav' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamav-update");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"clamav-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-db-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-debuginfo-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-devel-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-filesystem-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-lib-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-update-0.100.2-2.35.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamd-0.100.2-2.35.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-db / clamav-debuginfo / clamav-devel / etc");
}
