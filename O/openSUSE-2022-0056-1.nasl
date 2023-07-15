#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0056-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156648);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/12");

  script_cve_id(
    "CVE-2020-24504",
    "CVE-2020-27820",
    "CVE-2021-4001",
    "CVE-2021-4002",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-33098",
    "CVE-2021-43975",
    "CVE-2021-43976",
    "CVE-2021-45485",
    "CVE-2021-45486"
  );

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:0056-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0056-1 advisory.

  - Uncontrolled resource consumption in some Intel(R) Ethernet E810 Adapter drivers for Linux before version
    1.0.4 may allow an authenticated user to potentially enable denial of service via local access.
    (CVE-2020-24504)

  - A vulnerability was found in Linux kernel, where a use-after-frees in nouveau's postclose() handler could
    happen if removing device (that is not common to remove video card physically without power-off, but same
    happens if unbind the driver). (CVE-2020-27820)

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

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194266");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6QFPACQDVZMSNEBMXPO5WA2LCCPKDKR2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5de9e900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27820");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45486");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45485");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'cluster-md-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-devel-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-extra-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-livepatch-devel-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-optional-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-azure-5.3.18-38.34.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-azure-5.3.18-38.34.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-azure-5.3.18-38.34.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / kernel-azure / etc');
}
