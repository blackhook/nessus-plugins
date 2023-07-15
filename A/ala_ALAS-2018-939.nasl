#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-939.
#

include("compat.inc");

if (description)
{
  script_id(105517);
  script_version("3.15");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-5715", "CVE-2017-5754");
  script_xref(name:"ALAS", value:"2018-939");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2018-939) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated kernel release for Amazon Linux has been made available
which prevents speculative execution of indirect branches within the
kernel. This release incorporates latest stable open source Linux
security improvements to address CVE-2017-5715 within the kernel and
builds upon previously incorporated Kernel Page Table Isolation (KPTI)
that addressed CVE-2017-5754 . Customers must upgrade to the latest
Amazon Linux kernel or AMI to effectively mitigate the impact of both
CVE-2017-5754 and CVE-2017-5715 on MMU privilege separation (kernel
mode vs. user mode) within their instance.

Customers with existing Amazon Linux AMI instances should run the
following command to ensure they receive the updated package :

'sudo yum update kernel'

As is standard per any update of the Linux kernel, after the yum
update is complete, a reboot is required for updates to take effect.

Please refer to
https://aws.amazon.com/security/security-bulletins/AWS-2018-013/ for
additional information regarding CVE-2017-5754 .

Updated on 2018-01-06: Additional KPTI improvements.

Updated on 2018-01-09: Updated details

Updated on 2018-01-13: Additional fixes for CVE-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-939.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.76-3.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.76-3.78.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
