#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129129);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-3183",
    "CVE-2017-13693",
    "CVE-2017-13694",
    "CVE-2017-13695",
    "CVE-2017-18595",
    "CVE-2019-15090",
    "CVE-2019-15212",
    "CVE-2019-15213",
    "CVE-2019-15214",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15217",
    "CVE-2019-15917"
  );
  script_bugtraq_id(
    69766
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2019-1972)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in the Linux kernel before
    5.1.8. There is a double-free caused by a malicious USB
    device in the drivers/usb/misc/rio500.c
    driver.(CVE-2019-15212)

  - An issue was discovered in the Linux kernel before
    5.2.3. There is a use-after-free caused by a malicious
    USB device in the
    drivers/media/usb/dvb-usb/dvb-usb-init.c
    driver.(CVE-2019-15213)

  - An issue was discovered in the Linux kernel before
    5.2.6. There is a use-after-free caused by a malicious
    USB device in the drivers/media/usb/cpia2/cpia2_usb.c
    driver.(CVE-2019-15215)

  - An issue was discovered in the Linux kernel before
    5.0.14. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/usb/misc/yurex.c
    driver.(CVE-2019-15216)

  - An issue was discovered in the Linux kernel before
    5.2.3. There is a NULL pointer dereference caused by a
    malicious USB device in the
    drivers/media/usb/zr364xx/zr364xx.c
    driver.(CVE-2019-15217)

  - An issue was discovered in drivers/scsi/qedi/qedi_dbg.c
    in the Linux kernel before 5.1.12. In the qedi_dbg_*
    family of functions, there is an out-of-bounds
    read.(CVE-2019-15090)

  - An issue was discovered in the Linux kernel before
    4.14.11. A double free may be caused by the function
    allocate_trace_buffer in the file
    kernel/trace/trace.c.(CVE-2017-18595)

  - The acpi_ns_evaluate() function in
    drivers/acpi/acpica/nseval.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13695)

  - The acpi_ps_complete_final_op() function in
    drivers/acpi/acpica/psobject.c in the Linux kernel
    through 4.12.9 does not flush the node and node_ext
    caches and causes a kernel stack dump, which allows
    local users to obtain sensitive information from kernel
    memory and bypass the KASLR protection mechanism (in
    the kernel through 4.9) via a crafted ACPI
    table.(CVE-2017-13694)

  - The acpi_ds_create_operands() function in
    drivers/acpi/acpica/dsutils.c in the Linux kernel
    through 4.12.9 does not flush the operand cache and
    causes a kernel stack dump, which allows local users to
    obtain sensitive information from kernel memory and
    bypass the KASLR protection mechanism (in the kernel
    through 4.9) via a crafted ACPI table.(CVE-2017-13693)

  - Heap-based buffer overflow in the
    logi_dj_ll_raw_request function in
    drivers/hid/hid-logitech-dj.c in the Linux kernel
    before 3.16.2 allows physically proximate attackers to
    cause a denial of service (system crash) or possibly
    execute arbitrary code via a crafted device that
    specifies a large report size for an LED
    report.(CVE-2014-3183)

  - An issue was discovered in the Linux kernel before
    5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto()
    in drivers/bluetooth/hci_ldisc.c.(CVE-2019-15917)

  - An issue was discovered in the Linux kernel before
    5.0.10. There is a use-after-free in the sound
    subsystem because card disconnection causes certain
    data structures to be deleted too early. This is
    related to sound/core/init.c and
    sound/core/info.c.(CVE-2019-15214)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1972
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2550685");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "perf-3.10.0-862.14.1.2.h249.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.2.h249.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
