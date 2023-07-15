#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1086.
#

include("compat.inc");

if (description)
{
  script_id(118041);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/10");

  script_cve_id("CVE-2018-14633", "CVE-2018-16658", "CVE-2018-17182");
  script_xref(name:"ALAS", value:"2018-1086");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2018-1086)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A security flaw was found in the chap_server_compute_md5() function in
the ISCSI target code in the Linux kernel in a way an authentication
request from an ISCSI initiator is processed. An unauthenticated
remote attacker can cause a stack buffer overflow and smash up to 17
bytes of the stack. The attack requires the iSCSI target to be enabled
on the victim host. Depending on how the target's code was built (i.e.
depending on a compiler, compile flags and hardware architecture) an
attack may lead to a system crash and thus to a denial-of-service or
possibly to a non-authorized access to data exported by an iSCSI
target. Due to the nature of the flaw, privilege escalation cannot be
fully ruled out, although we believe it is highly
unlikely.(CVE-2018-14633 )

An information leak was discovered in the Linux kernel in
cdrom_ioctl_drive_status() function in drivers/cdrom/cdrom.c that
could be used by local attackers to read kernel memory at certain
location.(CVE-2018-16658 )

A security flaw was discovered in the Linux kernel. The
vmacache_flush_all() function in mm/vmacache.c mishandles sequence
number overflows. An attacker can trigger a use-after-free (and
possibly gain privileges) via certain thread creation, map, unmap,
invalidation, and dereference operations.(CVE-2018-17182 )"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1086.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Run 'yum update kernel' and reboot your instance to update your
system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-devel-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"kernel-headers-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-devel-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-debuginfo-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-4.14.72-73.55.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-debuginfo-4.14.72-73.55.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
