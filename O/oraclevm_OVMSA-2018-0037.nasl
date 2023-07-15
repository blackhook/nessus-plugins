#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0037.
#

include("compat.inc");

if (description)
{
  script_id(109426);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-12146", "CVE-2017-16643", "CVE-2017-16645", "CVE-2018-1093");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0037)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - scsi: iscsi_tcp: set BDI_CAP_STABLE_WRITES when data
    digest enabled (Jianchao Wang) [Orabug: 27726302]

  - block: fix bio_will_gap for first bvec with offset (Ming
    Lei) 

  - block: relax check on sg gap (Ming Lei) [Orabug:
    27775588]

  - block: don't optimize for non-cloned bio in
    bio_get_last_bvec (Ming Lei) [Orabug: 27775588]

  - block: merge: get the 1st and last bvec via helpers
    (Ming Lei) 

  - block: get the 1st and last bvec via helpers (Ming Lei)
    [Orabug: 27775588]

  - block: check virt boundary in bio_will_gap (Ming Lei)
    [Orabug: 27775588]

  - block: bio: introduce helpers to get the 1st and last
    bvec (Ming Lei) 

  - Failing to send a CLOSE if file is opened WRONLY and
    server reboots on a 4.x mount (Olga Kornievskaia)
    [Orabug: 27848303]

  - ext4: add validity checks for bitmap block numbers
    (Theodore Ts'o) [Orabug: 27854373] (CVE-2018-1093)
    (CVE-2018-1093)

  - ocfs2: Take inode cluster lock before moving reflinked
    inode from orphan dir (Ashish Samant) [Orabug: 27869411]

  - Input: gtco - fix potential out-of-bound access (Dmitry
    Torokhov) [Orabug: 27869844] (CVE-2017-16643)

  - Input: ims-psu - check if CDC union descriptor is sane
    (Dmitry Torokhov) [Orabug: 27870333] (CVE-2017-16645)

  - vfio/pci: Virtualize Maximum Payload Size (Alex
    Williamson)

  - vfio-pci: Virtualize PCIe & AF FLR (Alex Williamson)

  - uek-rpm: Disable DMA CMA (Jianchao Wang) [Orabug:
    27892359]

  - nvme-pci: fix multiple ctrl removal scheduling (Rakesh
    Pandit) 

  - nvme-pci: Fix nvme queue cleanup if IRQ setup fails
    (Jianchao Wang) 

  - nvme/pci: Fix stuck nvme reset (Keith Busch) [Orabug:
    27892359]

  - nvme: don't schedule multiple resets (Keith Busch)
    [Orabug: 27892359]

  - blk-mq: fix use-after-free in blk_mq_free_tag_set
    (Junichi Nomura) 

  - USB: core: prevent malicious bNumInterfaces overflow
    (Alan Stern) 

  - driver core: platform: fix race condition with
    driver_override (Adrian Salido) [Orabug: 27897874]
    (CVE-2017-12146)

  - usb/core: usb_alloc_dev: fix setting of ->portnum
    (Nicolai Stange)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-April/000848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e3f454d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.14.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.14.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
