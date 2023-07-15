##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163161);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2019-20808",
    "CVE-2021-3582",
    "CVE-2021-3592",
    "CVE-2021-3593",
    "CVE-2021-3594",
    "CVE-2021-3595",
    "CVE-2021-3607",
    "CVE-2021-3608",
    "CVE-2021-3748",
    "CVE-2021-3930",
    "CVE-2021-4145",
    "CVE-2021-20257",
    "CVE-2022-26354"
  );
  script_xref(name:"IAVB", value:"2022-B-0051-S");

  script_name(english:"EulerOS Virtualization 2.10.0 : qemu (EulerOS-SA-2022-2043)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - In QEMU 4.1.0, an out-of-bounds read flaw was found in the ATI VGA implementation. It occurs in the
    ati_cursor_define() routine while handling MMIO write operations through the ati_mm_write() callback. A
    malicious guest could abuse this flaw to crash the QEMU process, resulting in a denial of service.
    (CVE-2019-20808)

  - An infinite loop flaw was found in the e1000 NIC emulator of the QEMU. This issue occurs while processing
    transmits (tx) descriptors in process_tx_desc if various descriptor fields are initialized with invalid
    values. This flaw allows a guest to consume CPU cycles on the host, resulting in a denial of service. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20257)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device. The issue occurs while
    handling a 'PVRDMA_CMD_CREATE_MR' command due to improper memory remapping (mremap). This flaw allows a
    malicious guest to crash the QEMU process on the host. The highest threat from this vulnerability is to
    system availability. (CVE-2021-3582)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the bootp_input() function and could occur while processing a udp packet that is smaller than
    the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of
    uninitialized heap memory from the host. The highest threat from this vulnerability is to data
    confidentiality. This flaw affects libslirp versions prior to 4.6.0. (CVE-2021-3592)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3593)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the udp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3594)

  - An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw
    exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the
    size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory
    disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw
    affects libslirp versions prior to 4.6.0. (CVE-2021-3595)

  - An integer overflow was found in the QEMU implementation of VMWare's paravirtual RDMA device in versions
    prior to 6.1.0. The issue occurs while handling a 'PVRDMA_REG_DSRHIGH' write from the guest due to
    improper input validation. This flaw allows a privileged guest user to make QEMU allocate a large amount
    of memory, resulting in a denial of service. The highest threat from this vulnerability is to system
    availability. (CVE-2021-3607)

  - A flaw was found in the QEMU implementation of VMWare's paravirtual RDMA device in versions prior to
    6.1.0. The issue occurs while handling a 'PVRDMA_REG_DSRHIGH' write from the guest and may result in a
    crash of QEMU or cause undefined behavior due to the access of an uninitialized pointer. The highest
    threat from this vulnerability is to system availability. (CVE-2021-3608)

  - A use-after-free vulnerability was found in the virtio-net device of QEMU. It could occur when the
    descriptor's address belongs to the non direct access region, due to num_buffers being set after the
    virtqueue elem has been unmapped. A malicious guest could use this flaw to crash QEMU, resulting in a
    denial of service condition, or potentially execute code on the host with the privileges of the QEMU
    process. (CVE-2021-3748)

  - An off-by-one error was found in the SCSI device emulation in QEMU. It could occur while processing MODE
    SELECT commands in mode_sense_page() if the 'page' argument was set to MODE_PAGE_ALLS (0x3f). A malicious
    guest could use this flaw to potentially crash QEMU, resulting in a denial of service condition.
    (CVE-2021-3930)

  - A NULL pointer dereference issue was found in the block mirror layer of QEMU in versions prior to 6.2.0.
    The `self` pointer is dereferenced in mirror_wait_on_conflicts() without ensuring that it's not NULL. A
    malicious unprivileged user within the guest could use this flaw to crash the QEMU process on the host
    when writing data reaches the threshold of mirroring node. (CVE-2021-4145)

  - A flaw was found in the vhost-vsock device of QEMU. In case of error, an invalid element was not detached
    from the virtqueue before freeing its memory, leading to memory leakage and other unexpected results.
    Affected QEMU versions <= 6.2.0. (CVE-2022-26354)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d75e547");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3748");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "qemu-4.1.0-2.10.0.5.468"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
