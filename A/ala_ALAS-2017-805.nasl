#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-805.
#

include("compat.inc");

if (description)
{
  script_id(97557);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/27");

  script_cve_id("CVE-2016-7097", "CVE-2017-5551", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214");
  script_xref(name:"ALAS", value:"2017-805");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-805)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A use-after-free flaw was found in the way the Linux kernel's Datagram
Congestion Control Protocol (DCCP) implementation freed SKB (socket
buffer) resources for a DCCP_PKT_REQUEST packet when the
IPV6_RECVPKTINFO option is set on the socket. A local, unprivileged
user could use this flaw to alter the kernel memory, allowing them to
escalate their privileges on the system. (CVE-2017-6074)

A vulnerability was found in the Linux kernel. When file permissions
are modified via chmod and the user is not in the owning group or
capable of CAP_FSETID, the setgid bit is cleared in inode_change_ok().
Setting a POSIX ACL via setxattr sets the file permissions as well as
the new ACL, but doesn't clear the setgid bit in a similar way; this
allows to bypass the check in chmod. (CVE-2016-7097)

A vulnerability was found in the Linux kernel in 'tmpfs' file system.
When file permissions are modified via 'chmod' and the user is not in
the owning group or capable of CAP_FSETID, the setgid bit is cleared
in inode_change_ok(). Setting a POSIX ACL via 'setxattr' sets the file
permissions as well as the new ACL, but doesn't clear the setgid bit
in a similar way; this allows to bypass the check in 'chmod'.
(CVE-2017-5551)

An issue was found in the Linux kernel ipv6 implementation of GRE
tunnels which allows a remote attacker to trigger an out-of-bounds
access. (CVE-2017-5897)

It was discovered that an application may trigger a BUG_ON in
sctp_wait_for_sndbuf if the socket tx buffer is full, a thread is
waiting on it to queue more data, and meanwhile another thread peels
off the association being used by the first thread. (CVE-2017-5986)

A vulnerability was found in the Linux kernel where having malicious
IP options present would cause the ipv4_pktinfo_prepare() function to
drop/free the dst. This could result in a system crash or possible
privilege escalation. (CVE-2017-5970)

A flaw was found in the Linux kernel's handling of packets with the
URG flag. Applications using the splice() and tcp_splice_read()
functionality can allow a remote attacker to force the kernel to enter
a condition in which it can loop indefinitely. (CVE-2017-6214)

(Updated on 2017-03-21: CVE-2017-5970 was fixed in this release but
was previously not part of this errata.)

(Updated on 2017-06-07: CVE-2017-6214 was fixed in this release but
was previously not part of this errata.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-805.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.51-40.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.51-40.58.amzn1")) flag++;

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
