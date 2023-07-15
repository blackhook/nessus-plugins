#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-944.
#

include("compat.inc");

if (description)
{
  script_id(106171);
  script_version("3.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-17448", "CVE-2017-17450", "CVE-2017-17712", "CVE-2017-17741", "CVE-2017-8824");
  script_xref(name:"ALAS", value:"2018-944");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2018-944)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Race condition in raw_sendmsg function allows denial-of-service or
kernel addresses leak

A flaw was found in the Linux kernel's implementation of raw_sendmsg
allowing a local attacker to panic the kernel or possibly leak kernel
addresses. A local attacker, with the privilege of creating raw
sockets, can abuse a possible race condition when setting the socket
option to allow the kernel to automatically create ip header values
and thus potentially escalate their privileges. (CVE-2017-17712)

Use-after-free vulnerability in DCCP socket

A use-after-free vulnerability was found in DCCP socket code affecting
the Linux kernel since 2.6.16. This vulnerability could allow an
attacker to their escalate privileges. (CVE-2017-8824)

Stack-based out-of-bounds read via vmcall instruction

Linux kernel compiled with the KVM virtualization (CONFIG_KVM) support
is vulnerable to an out-of-bounds read access issue. It could occur
when emulating vmcall instructions invoked by a guest. A guest
user/process could use this flaw to disclose kernel memory bytes.
(CVE-2017-17741)

Unchecked capabilities in net/netfilter/xt_osf.c allows for
unprivileged modification to systemwide fingerprint list

net/netfilter/xt_osf.c in the Linux kernel through 4.14.4 does not
require the CAP_NET_ADMIN capability for add_callback and
remove_callback operations, which allows local users to bypass
intended access restrictions because the xt_osf_fingers data structure
is shared across all net namespaces. (CVE-2017-17450)

Missing capabilities check in net/netfilter/nfnetlink_cthelper.c
allows for unprivileged access to systemwide nfnl_cthelper_list
structure

net/netfilter/nfnetlink_cthelper.c in the Linux kernel through 4.14.4
does not require the CAP_NET_ADMIN capability for new, get, and del
operations, which allows local users to bypass intended access
restrictions because the nfnl_cthelper_list data structure is shared
across all net namespaces. (CVE-2017-17448)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-944.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.77-31.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.77-31.58.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
