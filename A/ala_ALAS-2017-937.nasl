#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-937.
#

include("compat.inc");

if (description)
{
  script_id(105422);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2017-0861", "CVE-2017-1000405", "CVE-2017-1000407", "CVE-2017-15115", "CVE-2017-16643", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16647", "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16994");
  script_xref(name:"ALAS", value:"2017-937");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-937) (Dirty COW)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw was found in the patches used to fix the 'dirtycow'
vulnerability (CVE-2016-5195). An attacker, able to run local code,
can exploit a race condition in transparent huge pages to modify
usually read-only huge pages. (CVE-2017-1000405)

Linux kernel Virtualization Module (CONFIG_KVM) for the Intel
processor family (CONFIG_KVM_INTEL) is vulnerable to a DoS issue. It
could occur if a guest was to flood the I/O port 0x80 with write
requests. A guest user could use this flaw to crash the host kernel
resulting in DoS. (CVE-2017-1000407)

A BUG in drivers/net/usb/asix_devices.c in the Linux kernel through
4.13.11 allows local users to cause a denial of service (NULL pointer
dereference and system crash) or possibly have unspecified other
impact via a crafted USB device. (CVE-2017-16647)

A BUG in drivers/media/usb/dvb-usb/dib0700_devices.c in the Linux
kernel through 4.13.11 allows local users to cause a denial of service
(BUG and system crash) or possibly have unspecified other impact via a
crafted USB device. (CVE-2017-16646)

The ims_pcu_get_cdc_union_desc function in
drivers/input/misc/ims-pcu.c in the Linux kernel through 4.13.11
allows local users to cause a denial of service
(ims_pcu_parse_cdc_data out-of-bounds read and system crash) or
possibly have unspecified other impact via a crafted USB device.
(CVE-2017-16645)

The parse_hid_report_descriptor function in
drivers/input/tablet/gtco.c in the Linux kernel before 4.13.11 allows
local users to cause a denial of service (out-of-bounds read and
system crash) or possibly have unspecified other impact via a crafted
USB device. (CVE-2017-16643)

The walk_hugetlb_range() function in 'mm/pagewalk.c' file in the Linux
kernel from v4.0-rc1 through v4.15-rc1 mishandles holes in hugetlb
ranges. This allows local users to obtain sensitive information from
uninitialized kernel memory via crafted use of the mincore() system
call. (CVE-2017-16994)

The qmi_wwan_bind function in drivers/net/usb/qmi_wwan.c in the Linux
kernel through 4.13.11 allows local users to cause a denial of service
(divide-by-zero error and system crash) or possibly have unspecified
other impact via a crafted USB device. (CVE-2017-16650)

The usbnet_generic_cdc_bind function in drivers/net/usb/cdc_ether.c in
the Linux kernel through 4.13.11 allows local users to cause a denial
of service (divide-by-zero error and system crash) or possibly have
unspecified other impact via a crafted USB device. (CVE-2017-16649)

A vulnerability was found in the Linux kernel when peeling off an
association to the socket in another network namespace. All transports
in this association are not to be rehashed and keep using the old key
in hashtable, thus removing transports from hashtable when closing the
socket, all transports are being freed. Later on a use-after-free
issue could be caused when looking up an association and dereferencing
the transports. (CVE-2017-15115)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-937.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.70-22.55.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.70-22.55.amzn1")) flag++;

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
