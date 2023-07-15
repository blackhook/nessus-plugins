#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0023.
#

include("compat.inc");

if (description)
{
  script_id(125664);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-12127", "CVE-2018-12130");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2019-0023) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL)");
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

  - x86/speculation/mds: Check for the right microcode
    before setting mitigation (Kanth Ghatraju) [Orabug:
    29797118]

  - vxlan: test dev->flags & IFF_UP before accessing
    vxlan->dev->dev_addr (Venkat Venkatsubra) [Orabug:
    29710939]

  - vxlan: test dev->flags & IFF_UP before calling
    gro_cells_receive (Eric Dumazet) [Orabug: 29710939]

  - nvme: allow timed-out ios to retry (James Smart)
    [Orabug: 29301607]

  - rds: Introduce a pool of worker threads for connection
    management (H&aring kon Bugge) [Orabug: 29391909]

  - rds: Use rds_conn_path cp_wq when applicable
    (H&aring kon Bugge) [Orabug: 29391909]

  - rds: ib: Implement proper cm_id compare (H&aring kon
    Bugge) [Orabug: 29391909]

  - Revert 'net/rds: prevent RDS connections using stale ARP
    entries' (H&aring kon Bugge) [Orabug: 29391909]

  - rds: ib: Flush ARP cache when needed (H&aring kon Bugge)
    [Orabug: 29391909]

  - rds: Add simple heuristics to determine connect delay
    (H&aring kon Bugge) [Orabug: 29391909]

  - rds: Fix one-sided connect (H&aring kon Bugge) [Orabug:
    29391909]

  - rds: Consolidate and align ftrace related to connection
    management (H&aring kon Bugge) [Orabug: 29391909]

  - rds: ib: Fix gratuitous ARP storm (H&aring kon Bugge)
    [Orabug: 29391909]

  - IB/mlx4: Increase the timeout for CM cache (H&aring kon
    Bugge) [Orabug: 29391909]

  - kvm/speculation: Allow KVM guests to use SSBD even if
    host does not (Alejandro Jimenez) [Orabug: 29423804]

  - x86/speculation: Keep enhanced IBRS on when
    spec_store_bypass_disable=on is used (Alejandro Jimenez)
    [Orabug: 29423804]

  - x86/speculation: Clean up enhanced IBRS checks in
    bugs_64.c (Alejandro Jimenez) [Orabug: 29423804]

  - mm: thp: relax __GFP_THISNODE for MADV_HUGEPAGE mappings
    (Andrea Arcangeli) [Orabug: 29510356]

  - bnxt_en: Reset device on RX buffer errors. (Michael
    Chan) [Orabug: 29651238]

  - x86/mitigations: Fix the test for Xen PV guest (Boris
    Ostrovsky) [Orabug: 29774291]

  - x86/speculation/mds: Fix verw usage to use memory
    operand (Kanth Ghatraju) [Orabug: 29791036]
    (CVE-2018-12127) (CVE-2018-12130)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2019-June/000942.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12130");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.27.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.27.2.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
