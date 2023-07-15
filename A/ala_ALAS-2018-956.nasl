#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-956.
#

include("compat.inc");

if (description)
{
  script_id(106933);
  script_version("3.7");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-1000405", "CVE-2017-17741", "CVE-2017-5753", "CVE-2018-1000028", "CVE-2018-5344", "CVE-2018-5750");
  script_xref(name:"ALAS", value:"2018-956");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2018-956) (Dirty COW) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Kernel address information leak in
drivers/acpi/sbshc.c:acpi_smbus_hc_add() function potentially allowing
KASLR bypass

The acpi_smbus_hc_add function in drivers/acpi/sbshc.c in the Linux
kernel, through 4.14.15, allows local users to obtain sensitive
address information by reading dmesg data from an SBS HC printk
call.(CVE-2018-5750)

Improper sorting of GIDs in nfsd can lead to incorrect permissions
being applied

Linux kernel contains a Incorrect Access Control vulnerability in NFS
server (nfsd) that can result in remote users reading or writing files
they should not be able to via NFS. This attack appear to be
exploitable via NFS server must export a filesystem with the
'rootsquash' options enabled. This vulnerability appears to have been
fixed in after commit 1995266727fa.(CVE-2018-1000028)

Stack-based out-of-bounds read via vmcall instruction

Linux kernel compiled with the KVM virtualization (CONFIG_KVM) support
is vulnerable to an out-of-bounds read access issue. It could occur
when emulating vmcall instructions invoked by a guest. A guest
user/process could use this flaw to disclose kernel memory
bytes.(CVE-2017-17741)

The pmd can become dirty without going through a COW cycle

A flaw was found in the patches used to fix the 'dirtycow'
vulnerability (CVE-2016-5195). An attacker, able to run local code,
can exploit a race condition in transparent huge pages to modify
usually read-only huge pages.(CVE-2017-1000405)

Speculative execution bounds-check bypass

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a
commonly used performance optimization). There are three primary
variants of the issue which differ in the way the speculative
execution can be exploited. Variant CVE-2017-5753 triggers the
speculative execution by performing a bounds-check bypass. It relies
on the presence of a precisely-defined instruction sequence in the
privileged code as well as the fact that memory accesses may cause
allocation into the microprocessor's data cache even for speculatively
executed instructions that never actually commit (retire). As a
result, an unprivileged attacker could use this flaw to cross the
syscall boundary and read privileged memory by conducting targeted
cache side-channel attacks.(CVE-2017-5753)

drivers/block/loop.c mishandles lo_release serialization allowing
denial-of-service

A flaw was found in the Linux kernel's handling of loopback devices.
An attacker, who has permissions to setup loopback disks, may create a
denial of service or other unspecified actions. (CVE-2018-5344)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-956.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/22");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.81-35.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.81-35.56.amzn1")) flag++;

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
