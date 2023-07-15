#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-925.
#

include("compat.inc");

if (description)
{
  script_id(104707);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-1000255", "CVE-2017-12190", "CVE-2017-12193", "CVE-2017-15299", "CVE-2017-15951");
  script_xref(name:"ALAS", value:"2017-925");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-925)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Incorrect updates of uninstantiated keys crash the kernel

A vulnerability was found in the key management subsystem of the Linux
kernel. An update on an uninstantiated key could cause a kernel panic,
leading to denial of service (DoS). (CVE-2017-15299)

Memory leak when merging buffers in SCSI IO vectors

It was found that in the Linux kernel through v4.14-rc5,
bio_map_user_iov() and bio_unmap_user() in 'block/bio.c' do unbalanced
pages refcounting if IO vector has small consecutive buffers belonging
to the same page. bio_add_pc_page() merges them into one, but the page
reference is never dropped, causing a memory leak and possible system
lockup due to out-of-memory condition. (CVE-2017-12190)

NULL pointer dereference due to incorrect node-splitting in
assoc_array implementation

A flaw was found in the Linux kernel's implementation of associative
arrays introduced in 3.13. This functionality was backported to the
3.10 kernels in Red Hat Enterprise Linux 7. The flaw involved a NULL
pointer dereference in assoc_array_apply_edit() due to incorrect
node-splitting in assoc_array implementation. This affects the keyring
key type and thus key addition and link creation operations may cause
the kernel to panic. (CVE-2017-12193)

Arbitrary stack overwrite causing oops via crafted signal frame

A flaw was found in the Linux kernel's handling of signal frame on
PowerPC systems. A malicious local user process could craft a signal
frame allowing an attacker to corrupt memory. (CVE-2017-1000255)

Race condition in the KEYS subsystem

The KEYS subsystem in the Linux kernel before 4.13.10 does not
correctly synchronize the actions of updating versus finding a key in
the 'negative' state to avoid a race condition, which allows local
users to cause a denial of service or possibly have unspecified other
impact via crafted system calls. (CVE-2017-15951)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-925.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.62-21.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.62-21.56.amzn1")) flag++;

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
