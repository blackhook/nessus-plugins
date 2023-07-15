#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0181-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157076);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-4001",
    "CVE-2021-4002",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-33098",
    "CVE-2021-43975",
    "CVE-2021-43976"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0181-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:0181-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0181-1 advisory.

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

  - Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow
    an authenticated user to potentially enable denial of service via local access. (CVE-2021-33098)

  - A race condition was found in the Linux kernel's ebpf verifier between bpf_map_update_elem and
    bpf_map_freeze due to a missing lock in kernel/bpf/syscall.c. In this flaw, a local user with a special
    privilege (cap_sys_admin or cap_bpf) can modify the frozen mapped address space. This flaw affects kernel
    versions prior to 5.16 rc2. (CVE-2021-4001)

  - A flaw use-after-free in function sco_sock_sendmsg() of the Linux kernel HCI subsystem was found in the
    way user calls ioct UFFDIO_REGISTER or other way triggers race condition of the call sco_conn_del()
    together with the call sco_sock_sendmsg() with the expected controllable faulting memory page. A
    privileged local user could use this flaw to crash the system or escalate their privileges on the system.
    (CVE-2021-3640) (CVE-2021-4002)

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193442");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-January/010073.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4fc18f7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43976");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-43975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'dlm-kmp-rt-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'gfs2-kmp-rt-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-devel-rt-5.3.18-65.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-devel-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-devel-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-source-rt-5.3.18-65.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-syms-rt-5.3.18-65.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'ocfs2-kmp-rt-5.3.18-65.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
