#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1405.
#

include('compat.inc');

if (description)
{
  script_id(134896);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2020-2732", "CVE-2020-8648", "CVE-2020-10942");
  script_xref(name:"ALAS", value:"2020-1405");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1405)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A flaw was found in the way KVM hypervisor handled instruction
emulation for the L2 guest when nested(=1) virtualization is enabled.
In the instruction emulation, the L2 guest could trick the L0
hypervisor into accessing sensitive bits of the L1 hypervisor. An L2
guest could use this flaw to potentially access information of the L1
hypervisor. (CVE-2020-2732)

There is a use-after-free vulnerability in the Linux kernel through
5.5.2 in the n_tty_receive_buf_common function in drivers/tty/n_tty.
(CVE-2020-8648)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1405.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10942");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.173-137.228");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-devel-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"kernel-headers-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-livepatch-4.14.173-137.228-1.0-0.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-devel-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-debuginfo-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-4.14.173-137.228.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-debuginfo-4.14.173-137.228.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
