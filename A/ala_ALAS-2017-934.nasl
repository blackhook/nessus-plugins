#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-934.
#

include("compat.inc");

if (description)
{
  script_id(105419);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-14167", "CVE-2017-15289");
  script_xref(name:"ALAS", value:"2017-934");

  script_name(english:"Amazon Linux AMI : qemu-kvm (ALAS-2017-934)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Quick Emulator (QEMU), compiled with the PC System Emulator with
multiboot feature support, is vulnerable to an OOB r/w memory access
issue. The issue could occur due to an integer overflow while loading
a kernel image during a guest boot. A user or process could use this
flaw to potentially achieve arbitrary code execution on a host.
(CVE-2017-14167)

Quick emulator (QEMU), compiled with the Cirrus CLGD 54xx VGA Emulator
support, is vulnerable to an OOB write access issue. The issue could
occur while writing to VGA memory via mode4and5 write functions. A
privileged user inside guest could use this flaw to crash the QEMU
process resulting in Denial of Serivce (DoS). (CVE-2017-15289)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-934.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update qemu-kvm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/26");
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
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-img-1.5.3-141.5.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-1.5.3-141.5.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-141.5.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-141.5.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-141.5.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / etc");
}
