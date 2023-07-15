#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1322.
#

include("compat.inc");

if (description)
{
  script_id(131242);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2018-12207");
  script_xref(name:"ALAS", value:"2019-1322");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2019-1322)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way Intel CPUs handle inconsistency between,
virtual to physical memory address translations in CPU's local cache
and system software's Paging structure entries. A privileged guest
user may use this flaw to induce a hardware Machine Check Error on the
host processor, resulting in a severe DoS scenario by halting the
processor.

System software like OS OR Virtual Machine Monitor (VMM) use virtual
memory system for storing program instructions and data in memory.
Virtual Memory system uses Paging structures like Page Tables and Page
Directories to manage system memory. The processor's Memory Management
Unit (MMU) uses Paging structure entries to translate program's
virtual memory addresses to physical memory addresses. The processor
stores these address translations into its local cache buffer called -
Translation Lookaside Buffer (TLB). TLB has two parts, one for
instructions and other for data addresses.

System software can modify its Paging structure entries to change
address mappings OR certain attributes like page size etc. Upon such
Paging structure alterations in memory, system software must
invalidate the corresponding address translations in the processor's
TLB cache. But before this TLB invalidation takes place, a privileged
guest user may trigger an instruction fetch operation, which could use
an already cached, but now invalid, virtual to physical address
translation from Instruction TLB (ITLB). Thus accessing an invalid
physical memory address and resulting in halting the processor due to
the Machine Check Error (MCE) on Page Size Change. (CVE-2018-12207)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1322.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.14.154-99.181.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.14.154-99.181.amzn1")) flag++;

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
