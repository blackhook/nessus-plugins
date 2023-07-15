#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151557);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-25084",
    "CVE-2020-35504",
    "CVE-2020-35505",
    "CVE-2021-3527",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-20181",
    "CVE-2021-20221"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : qemu (EulerOS-SA-2021-2211)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A NULL pointer dereference flaw was found in the SCSI
    emulation support of QEMU in versions before 6.0.0.
    This flaw allows a privileged guest user to crash the
    QEMU process on the host, resulting in a denial of
    service. The highest threat from this vulnerability is
    to system availability.(CVE-2020-35504)

  - An out-of-bounds heap buffer access issue was found in
    the ARM Generic Interrupt Controller emulator of QEMU
    up to and including qemu 4.2.0on aarch64 platform. The
    issue occurs because while writing an interrupt ID to
    the controller memory area, it is not masked to be 4
    bits wide. It may lead to the said issue while updating
    controller state fields and their subsequent
    processing. A privileged guest user may use this flaw
    to crash the QEMU process on the host resulting in DoS
    scenario.(CVE-2021-20221)

  - A flaw was found in the USB redirector device
    (usb-redir) of QEMU. Small USB packets are combined
    into a single, large transfer request, to reduce the
    overhead and improve performance. The combined size of
    the bulk transfer is used to dynamically allocate a
    variable length array (VLA) on the stack without proper
    validation. Since the total size is not bounded, a
    malicious guest could use this flaw to influence the
    array length and cause the QEMU process to perform an
    excessive allocation on the(CVE-2021-3527)

  - QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c
    because the usb_packet_map return value is not
    checked.(CVE-2020-25084)

  - A NULL pointer dereference flaw was found in the
    am53c974 SCSI host bus adapter emulation of QEMU in
    versions before 6.0.0. This issue occurs while handling
    the 'Information Transfer' command. This flaw allows a
    privileged guest user to crash the QEMU process on the
    host, resulting in a denial of service. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-35505)

  - An information disclosure vulnerability was found in
    the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw
    exists in virgl_cmd_get_capset_info() in
    contrib/vhost-user-gpu/virgl.c and could occur due to
    the read of uninitialized memory. A malicious guest
    could exploit this issue to leak memory from the host.
    (CVE-2021-3545)

  - Several memory leaks were found in the virtio
    vhost-user GPU device (vhost-user-gpu) of QEMU in
    versions up to and including 6.0. They exist in
    contrib/vhost-user-gpu/vhost-user-gpu.c and
    contrib/vhost-user-gpu/virgl.c due to improper release
    of memory (i.e., free) after effective
    lifetime.(CVE-2021-3544)

  - A flaw was found in vhost-user-gpu of QEMU in versions
    up to and including 6.0. An out-of-bounds write
    vulnerability can allow a malicious guest to crash the
    QEMU process on the host resulting in a denial of
    service or potentially execute arbitrary code on the
    host with the privileges of the QEMU process. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2021-3546)

  - A race condition flaw was found in the 9pfs server
    implementation of QEMU up to and including 5.2.0. This
    flaw allows a malicious 9p client to cause a
    use-after-free error, potentially escalating their
    privileges on the system. The highest threat from this
    vulnerability is to confidentiality, integrity as well
    as system availability.(CVE-2021-20181)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?069e25b9");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20181");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qemu-4.1.0-2.9.1.2.285",
        "qemu-img-4.1.0-2.9.1.2.285"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
