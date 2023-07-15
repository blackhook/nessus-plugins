#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-22.
#

include("compat.inc");

if (description)
{
  script_id(69581);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2011-1083", "CVE-2011-4077", "CVE-2011-4081");
  script_xref(name:"ALAS", value:"2011-22");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2011-22)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The epoll implementation in the Linux kernel 2.6.37.2 and earlier does
not properly traverse a tree of epoll file descriptors, which allows
local users to cause a denial of service (CPU consumption) via a
crafted application that makes epoll_create and epoll_ctl system
calls.

Buffer overflow in the xfs_readlink function in fs/xfs/xfs_vnodeops.c
in XFS in the Linux kernel 2.6, when CONFIG_XFS_DEBUG is disabled,
allows local users to cause a denial of service (memory corruption and
crash) and possibly execute arbitrary code via an XFS image containing
a symbolic link with a long pathname.

crypto/ghash-generic.c in the Linux kernel before 3.1 allows local
users to cause a denial of service (NULL pointer dereference and OOPS)
or possibly have unspecified other impact by triggering a failed or
missing ghash_setkey function call, followed by a (1) ghash_update
function call or (2) ghash_final function call, as demonstrated by a
write operation on an AF_ALG socket."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-22.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"kernel-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-2.6.35.14-103.47.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-2.6.35.14-103.47.amzn1")) flag++;

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
