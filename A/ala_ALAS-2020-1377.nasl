#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1377.
#

include('compat.inc');

if (description)
{
  script_id(137100);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2019-19319",
    "CVE-2019-19768",
    "CVE-2020-1749",
    "CVE-2020-10751",
    "CVE-2020-12770"
  );
  script_xref(name:"ALAS", value:"2020-1377");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2020-1377)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In the Linux kernel 5.0.21, a setxattr operation, after a mount of a
crafted ext4 image, can cause a slab-out-of-bounds write access
because of an ext4_xattr_set_entry use-after-free in fs/ext4/xattr.c
when a large old_size value is used in a memset call.(CVE-2019-19319)

In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the
__blk_add_trace function in kernel/trace/blktrace.c (which is used to
fill out a blk_io_trace structure and place it in a per-cpu
sub-buffer).(CVE-2019-19768)

A flaw was found in the Linux kernels SELinux LSM hook implementation
before version 5.7, where it incorrectly assumed that an skb would
only contain a single netlink message. The hook would incorrectly only
validate the first netlink message in the skb and allow or deny the
rest of the messages within the skb with the granted permission
without further processing.(CVE-2020-10751)

An issue was discovered in the Linux kernel through 5.6.11. sg_write
lacks an sg_remove_request call in a certain failure case, aka
CID-83c6f2390040.(CVE-2020-12770)

A flaw was found in the Linux kernel's implementation of some
networking protocols in IPsec, such as VXLAN and GENEVE tunnels over
IPv6. When an encrypted tunnel is created between two hosts, the
kernel isn't correctly routing tunneled data over the encrypted link;
rather sending the data unencrypted. This would allow anyone in
between the two endpoints to read the traffic unencrypted. The main
threat from this vulnerability is to data
confidentiality.(CVE-2020-1749)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1377.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1749");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.14.181-108.257.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.14.181-108.257.amzn1")) flag++;

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
