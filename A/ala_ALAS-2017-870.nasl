#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-870.
#

include("compat.inc");

if (description)
{
  script_id(102544);
  script_version("3.5");
  script_cvs_date("Date: 2019/04/10 16:10:16");

  script_cve_id("CVE-2017-11473", "CVE-2017-7533", "CVE-2017-7542", "CVE-2017-8831");
  script_xref(name:"ALAS", value:"2017-870");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-870)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in mp_override_legacy_irq() :

Buffer overflow in the mp_override_legacy_irq() function in
arch/x86/kernel/acpi/boot.c in the Linux kernel through 4.12.2 allows
local users to gain privileges via a crafted ACPI table.
(CVE-2017-11473)

A race between inotify_handle_event() and sys_rename() :

A race condition was found in the Linux kernel, present since
v3.14-rc1 through v4.12. The race happens between threads of
inotify_handle_event() and vfs_rename() while running the rename
operation against the same file. As a result of the race the next slab
data or the slab's free list pointer can be corrupted with
attacker-controlled data, which may lead to the privilege escalation.
(CVE-2017-7533)

Integer overflow in ip6_find_1stfragopt() causes infinite loop :

An integer overflow vulnerability in ip6_find_1stfragopt() function
was found. A local attacker that has privileges (of CAP_NET_RAW) to
open raw socket can cause an infinite loop inside the
ip6_find_1stfragopt() function.(CVE-2017-7542)

Double fetch vulnerability in saa7164_bus_get function The
saa7164_bus_get function in drivers/media/pci/saa7164/saa7164-bus.c in
the Linux kernel through 4.10.14 allows local users to cause a denial
of service (out-of-bounds array access) or possibly have unspecified
other impact by changing a certain sequence-number value, aka a
'double fetch' vulnerability. Please note, the saa7164 driver is not
enabled in the Amazon Linux AMI kernel (CVE-2017-8831)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-870.html"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"kernel-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.43-17.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.43-17.38.amzn1")) flag++;

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
