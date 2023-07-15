#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0284.
#

include("compat.inc");

if (description)
{
  script_id(119292);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2018-1000204", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18710");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0284)");
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

  - Revert commit 8bd274934987 ('block: fix bdi vs gendisk
    lifetime mismatch') (Ashish Samant) [Orabug: 28968102]

  - KVM/x86: Add IBPB support (Ashok Raj) [Orabug: 28703712]

  - x86/intel/spectre_v2: Remove unnecessary retp_compiler
    test (Boris Ostrovsky) [Orabug: 28814570]

  - x86/intel/spectre_v4: Deprecate
    spec_store_bypass_disable=userspace (Boris Ostrovsky)
    [Orabug: 28814570]

  - x86/speculation: x86_spec_ctrl_set needs to be called
    unconditionally (Boris Ostrovsky) [Orabug: 28814570]

  - x86/speculation: Drop unused DISABLE_IBRS_CLOBBER macro
    (Boris Ostrovsky) [Orabug: 28814570]

  - x86/intel/spectre_v4: Keep SPEC_CTRL_SSBD when IBRS is
    in use (Boris Ostrovsky) [Orabug: 28814570]

  - net: net_failover: fix typo in
    net_failover_slave_register (Liran Alon) [Orabug:
    28122104]

  - virtio_net: Extend virtio to use VF datapath when
    available (Sridhar Samudrala) [Orabug: 28122104]

  - virtio_net: Introduce VIRTIO_NET_F_STANDBY feature bit
    (Sridhar Samudrala) [Orabug: 28122104]

  - net: Introduce net_failover driver (Sridhar Samudrala)
    [Orabug: 28122104]

  - net: Introduce generic failover module (Sridhar
    Samudrala) [Orabug: 28122104]

  - net: introduce lower state changed info structure for
    LAG lowers (Jiri Pirko) [Orabug: 28122104]

  - net: introduce change lower state notifier (Jiri Pirko)
    [Orabug: 28122104]

  - net: add info struct for LAG changeupper (Jiri Pirko)
    [Orabug: 28122104]

  - net: add possibility to pass information about upper
    device via notifier (Jiri Pirko) [Orabug: 28122104]

  - net: Check CHANGEUPPER notifier return value (Ido
    Schimmel) [Orabug: 28122104]

  - net: introduce change upper device notifier change info
    (Jiri Pirko) 

  - x86/bugs: rework x86_spec_ctrl_set to make its changes
    explicit (Daniel Jordan) [Orabug: 28271063]

  - x86/bugs: rename ssbd_ibrs_selected to
    ssbd_userspace_selected (Daniel Jordan) [Orabug:
    28271063]

  - x86/bugs: always use x86_spec_ctrl_base or _priv when
    setting spec ctrl MSR (Daniel Jordan) [Orabug: 28271063]

  - xen-blkfront: fix kernel panic with negotiate_mq error
    path (Manjunath Patil) [Orabug: 28798861]

  - scsi: lpfc: Correct MDS diag and nvmet configuration
    (James Smart) 

  - scsi: virtio_scsi: let host do exception handling (Paolo
    Bonzini) 

  - net/rds: Fix endless RNR situation (Venkat Venkatsubra)
    [Orabug: 28857027]

  - scsi: sg: allocate with __GFP_ZERO in sg_build_indirect
    (Alexander Potapenko) [Orabug: 28892656]
    (CVE-2018-1000204)

  - cdrom: fix improper type cast, which can leat to
    information leak. (Young_X) [Orabug: 28929767]
    (CVE-2018-16658) (CVE-2018-10940) (CVE-2018-18710)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-November/000918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99e26a29"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000204");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.22.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.22.4.el6uek")) flag++;

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
