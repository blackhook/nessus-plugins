#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1401.
#

include("compat.inc");

if (description)
{
  script_id(138643);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2018-20669", "CVE-2019-19462", "CVE-2020-0543", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-12771");
  script_xref(name:"ALAS", value:"2020-1401");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2020-1401)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue where a provided address with access_ok() is not checked was
discovered in i915_gem_execbuffer2_ioctl in
drivers/gpu/drm/i915/i915_gem_execbuffer.c in the Linux kernel through
4.19.13. A local attacker can craft a malicious IOCTL function call to
overwrite arbitrary kernel memory, resulting in a Denial of Service or
privilege escalation. (CVE-2018-20669)

A flaw was found in the prctl() function, where it can be used to
enable indirect branch speculation after it has been disabled. This
call incorrectly reports it as being 'force disabled' when it is not
and opens the system to Spectre v2 attacks. The highest threat from
this vulnerability is to confidentiality. (CVE-2020-10768)

A new domain bypass transient execution attack known as Special
Register Buffer Data Sampling (SRBDS) has been found. This flaw allows
data values from special internal registers to be leaked by an
attacker able to execute code on any core of the CPU. An unprivileged,
local attacker can use this flaw to infer values returned by affected
instructions known to be commonly used during cryptographic operations
that rely on uniqueness, secrecy, or both. Incomplete cleanup from
specific special register read operations in some Intel(R) Processors
may allow an authenticated user to potentially enable information
disclosure via local access. (CVE-2020-0543)

relay_open in kernel/relay.c in the Linux kernel through 5.4.1 allows
local users to cause a denial of service (such as relay blockage) by
triggering a NULL alloc_percpu result. (CVE-2019-19462)

A logic bug flaw was found in the Linux kernel's implementation of
SSBD. A bug in the logic handling allows an attacker with a local
account to disable SSBD protection during a context switch when
additional speculative execution mitigations are in place. This issue
was introduced when the per task/process conditional STIPB switching
was added on top of the existing SSBD switching. The highest threat
from this vulnerability is to confidentiality. (CVE-2019-19462)

A flaw was found in the Linux kernel's implementation of the Enhanced
IBPB (Indirect Branch Prediction Barrier). The IBPB mitigation will be
disabled when STIBP is not available or when the Enhanced Indirect
Branch Restricted Speculation (IBRS) is available. This flaw allows a
local attacker to perform a Spectre V2 style attack when this
configuration is active. The highest threat from this vulnerability is
to confidentiality. (CVE-2019-19462)

An issue was discovered in the Linux kernel through 5.6.11.
btree_gc_coalesce in drivers/md/bcache/btree.c has a deadlock if a
coalescing operation fails. (CVE-2020-12771)

A flaw was found in the Linux kernel's implementation of Userspace
core dumps. This flaw allows an attacker with a local account to crash
a trivial program and exfiltrate private kernel data. (CVE-2020-10732)

A flaw was found in the Linux Kernel in versions after 4.5-rc1 in the
way mremap handled DAX Huge Pages. This flaw allows a local attacker
with access to a DAX enabled storage to escalate their privileges on
the system. (CVE-2020-10757)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1401.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.14.186-110.268.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.14.186-110.268.amzn1")) flag++;

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
