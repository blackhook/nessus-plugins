#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0253.
#

include("compat.inc");

if (description)
{
  script_id(112282);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2018-10021", "CVE-2018-10938", "CVE-2018-13405", "CVE-2018-15594");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0253)");
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

  - rebuild bumping release

  - Cipso: cipso_v4_optptr enter infinite loop (yujuan.qi)
    [Orabug: 28563992] (CVE-2018-10938)

  - Btrfs: fix list_add corruption and soft lockups in fsync
    (Liu Bo) 

  - x86/paravirt: Fix spectre-v2 mitigations for paravirt
    guests (Peter Zijlstra) [Orabug: 28474643]
    (CVE-2018-15594)

  - sym53c8xx: fix NULL pointer dereference panic in
    sym_int_sir in sym_hipd.c (George Kennedy) [Orabug:
    28481893]

  - md/raid1: Avoid raid1 resync getting stuck (Jes
    Sorensen) [Orabug: 28529228]

  - x86/spectrev2: Don't set mode to SPECTRE_V2_NONE when
    retpoline is available. (Boris Ostrovsky) [Orabug:
    28540376]

  - ext4: avoid deadlock when expanding inode size (Jan
    Kara) [Orabug: 25718971]

  - ext4: properly align shifted xattrs when expanding
    inodes (Jan Kara) 

  - ext4: fix xattr shifting when expanding inodes part 2
    (Jan Kara) 

  - ext4: fix xattr shifting when expanding inodes (Jan
    Kara) [Orabug: 25718971]

  - uek-rpm: Enable perf stripped binary (Victor Erminpour)
    [Orabug: 27801171]

  - nfsd: give out fewer session slots as limit approaches
    (J. Bruce Fields) [Orabug: 28023821]

  - nfsd: increase DRC cache limit (J. Bruce Fields)
    [Orabug: 28023821]

  - uek-rpm: config-debug: Turn off torture testing by
    default (Knut Omang) [Orabug: 28261886]

  - ipmi: Remove smi_msg from waiting_rcv_msgs list before
    handle_one_recv_msg (Junichi Nomura)

  - x86/mce/AMD: Give a name to MCA bank 3 when accessed
    with legacy MSRs (Yazen Ghannam) [Orabug: 28416303]

  - Fix up non-directory creation in SGID directories (Linus
    Torvalds) [Orabug: 28459477] (CVE-2018-13405)

  - scsi: libsas: defer ata device eh commands to libata
    (Jason Yan) [Orabug: 28459685] (CVE-2018-10021)

  - PCI: Allocate ATS struct during enumeration (Bjorn
    Helgaas) [Orabug: 28460092]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-September/000888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8217169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/05");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.18.9.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.18.9.el6uek")) flag++;

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
