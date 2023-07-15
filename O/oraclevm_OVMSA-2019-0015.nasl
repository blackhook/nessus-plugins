#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0015.
#

include("compat.inc");

if (description)
{
  script_id(124638);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/21");

  script_cve_id("CVE-2017-13305");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0015)");
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

  - x86/apic: Make arch_setup_hwirq NUMA node aware (Henry
    Willard) [Orabug: 29534769]

  - KEYS: encrypted: fix buffer overread in
    valid_master_desc (Eric Biggers) [Orabug: 29591025]
    (CVE-2017-13305)

  - scsi: target: remove hardcoded T10 Vendor ID in INQUIRY
    response (Alan Adamson) [Orabug: 29344862]

  - scsi: target: add device vendor id, product id and
    revision configfs attributes (Alan Adamson) [Orabug:
    29344862]

  - scsi: target: consistently null-terminate t10_wwn
    strings (David Disseldorp) [Orabug: 29344862]

  - scsi: target: use consistent left-aligned ASCII INQUIRY
    data (David Disseldorp) [Orabug: 29344862]

  - ext4: fix data corruption caused by unaligned direct AIO
    (Lukas Czerner) [Orabug: 29553371]

  - swiotlb: checking whether swiotlb buffer is full with
    io_tlb_used (Dongli Zhang) [Orabug: 29582587]

  - swiotlb: add debugfs to track swiotlb buffer usage
    (Dongli Zhang) [Orabug: 29582587]

  - swiotlb: fix comment on swiotlb_bounce (Dongli Zhang)
    [Orabug: 29582587]

  - NFSv4.1: nfs4_fl_prepare_ds must be careful about
    reporting success. (NeilBrown) [Orabug: 29617508]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2019-May/000937.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.26.10.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.26.10.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
