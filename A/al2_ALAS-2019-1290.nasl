#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1290.
#

include("compat.inc");

if (description)
{
  script_id(129069);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2018-12179", "CVE-2018-12182", "CVE-2018-12183", "CVE-2019-0160", "CVE-2019-0161");
  script_xref(name:"ALAS", value:"2019-1290");

  script_name(english:"Amazon Linux 2 : edk2 (ALAS-2019-1290)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Insufficient memory write check in SMM service for EDK II may allow an
authenticated user to potentially enable escalation of privilege,
information disclosure and/or denial of service via local access.
(CVE-2018-12182)

Stack overflow in XHCI for EDK II may allow an unauthenticated user to
potentially enable denial of service via local access. (CVE-2019-0161)

Buffer overflows were discovered in UDF-related codes under
MdeModulePkg\Universal\Disk\PartitionDxe\Udf.c and
MdeModulePkg\Universal\Disk\UdfDxe, which could be triggered with long
file names or invalid formatted UDF media. (CVE-2019-0160)

Stack overflow in DxeCore for EDK II may allow an unauthenticated user
to potentially enable escalation of privilege, information disclosure
and/or denial of service via local access. (CVE-2018-12183)

Improper configuration in system firmware for EDK II may allow
unauthenticated user to potentially enable escalation of privilege,
information disclosure and/or denial of service via local access.
(CVE-2018-12179)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1290.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update edk2' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");
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
if (rpm_check(release:"AL2", reference:"edk2-aarch64-20190501stable-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"edk2-debuginfo-20190501stable-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-ovmf-20190501stable-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"edk2-tools-20190501stable-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-tools-doc-20190501stable-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-tools-python-20190501stable-2.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk2-aarch64 / edk2-debuginfo / edk2-ovmf / edk2-tools / etc");
}
