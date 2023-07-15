#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0033.
#

include("compat.inc");

if (description)
{
  script_id(109114);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2017-17052", "CVE-2017-7518");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0033)");
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

  - mlx4: change the ICM table allocations to lowest needed
    size (Daniel Jurgens) [Orabug: 27718305]

  - autofs: use dentry flags to block walks during expire
    (Ian Kent) 

  - autofs races (Al Viro) [Orabug: 27766149] [Orabug:
    27766149]

  - crypto: FIPS - allow tests to be disabled in FIPS mode
    (Stephan Mueller) [Orabug: 26182706]

  - crypto: rng - Zero seed in crypto_rng_reset (Herbert Xu)
    [Orabug: 26182706]

  - crypto: xts - consolidate sanity check for keys (Stephan
    Mueller) 

  - fork: fix incorrect fput of ->exe_file causing
    use-after-free (Eric Biggers) [Orabug: 27290198]
    (CVE-2017-17052)

  - negotiate_mq should happen in all cases of a new VBD
    being discovered by xen-blkfront, whether called through
    _probe or a hot-attached new VBD from dom-0 via
    xenstore. Otherwise, hot-attached new VBDs are left
    configured without multi-queue. (Patrick Colp) [Orabug:
    27383895]

  - rds: Fix NULL pointer dereference in __rds_rdma_map
    (H&aring kon Bugge) 

  - nvme: fix uninitialized prp2 value on small transfers
    (Jan H. Sch&ouml nherr) [Orabug: 27581008]

  - xen-netfront: Improve error handling during
    initialization (Ross Lagerwall) [Orabug: 27655820]

  - RDS: IB: Fix null pointer issue (Guanglei Li) [Orabug:
    27636704]

  - mstflint: update Makefile and Kconfig (Qing Huang)
    [Orabug: 27656465]

  - target: add inquiry_product module param to override LIO
    default (Kyle Fortin) [Orabug: 27679482]

  - target: add inquiry_vendor module param to override
    LIO-ORG (Kyle Fortin) [Orabug: 27679482]

  - net/rds: Avoid copy overhead if send buff is full (Gerd
    Rausch) 

  - IB/core: Avoid calling ib_query_device (Or Gerlitz)
    [Orabug: 27687710]

  - IB/core: Save the device attributes on the device
    structure (Ira Weiny) [Orabug: 27687710]

  - KVM: x86: fix singlestepping over syscall (Paolo
    Bonzini) [Orabug: 27669907] (CVE-2017-7518)
    (CVE-2017-7518)

  - xen/acpi: upload _PSD info for non-dom0 CPUs too (Joao
    Martins) 

  - Revert 'RDS: don't commit to queue till transport
    connection is up' (Santosh Shilimkar)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-April/000842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca78dd73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-112.16.7.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-112.16.7.el6uek")) flag++;

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
