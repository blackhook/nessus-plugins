#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1335.
#

include("compat.inc");

if (description)
{
  script_id(133005);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2019-15961");
  script_xref(name:"ALAS", value:"2020-1335");

  script_name(english:"Amazon Linux AMI : clamav (ALAS-2020-1335)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability in the email parsing module Clam AntiVirus (ClamAV)
Software versions 0.102.0, 0.101.4 and prior could allow an
unauthenticated, remote attacker to cause a denial of service
condition on an affected device. The vulnerability is due to
inefficient MIME parsing routines that result in extremely long scan
times of specially formatted email files. An attacker could exploit
this vulnerability by sending a crafted email file to an affected
device. An exploit could allow the attacker to cause the ClamAV
scanning process to scan the crafted email file indefinitely,
resulting in a denial of service condition. (CVE-2019-15961)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1335.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update clamav' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15961");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"clamav-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-data-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-db-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-debuginfo-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-devel-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-filesystem-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-lib-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-milter-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamav-update-0.101.5-1.42.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"clamd-0.101.5-1.42.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-data / clamav-db / clamav-debuginfo / clamav-devel / etc");
}
