#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1392.
#

include("compat.inc");

if (description)
{
  script_id(133556);
  script_version("1.2");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2019-19062", "CVE-2019-19332");
  script_xref(name:"ALAS", value:"2020-1392");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1392)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory leak in the crypto_report() function in
crypto/crypto_user_base.c in the Linux kernel through 5.3.11 allows
attackers to cause a denial of service (memory consumption) by
triggering crypto_report_alg() failures, aka CID-ffdde5932042.
(CVE-2019-19062)

An out-of-bounds memory write issue was found in the Linux Kernel,
version 3.13 through 5.4, in the way the Linux kernel's KVM hypervisor
handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
features emulated by the KVM hypervisor. A user or process able to
access the '/dev/kvm' device could use this flaw to crash the system,
resulting in a denial of service. (CVE-2019-19332)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1392.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19332");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.165-131.185");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-devel-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"kernel-headers-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-livepatch-4.14.165-131.185-1.0-0.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-devel-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-debuginfo-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-4.14.165-131.185.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-debuginfo-4.14.165-131.185.amzn2")) flag++;

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
