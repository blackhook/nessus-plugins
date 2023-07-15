#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1888-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150696);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2021-3491",
    "CVE-2021-23134",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1888-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:1888-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:1888-1 advisory.

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the ALFA Windows 10 driver 6.1316.1209 for AWUS036H. The Wi-Fi implementation
    does not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can
    abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-
    confidentiality protocol. (CVE-2020-26141)

  - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3
    implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process
    them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets
    independent of the network configuration. (CVE-2020-26145)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability. (CVE-2021-23134)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - kernel/bpf/verifier.c in the Linux kernel through 5.12.7 enforces incorrect limits for pointer arithmetic
    operations, aka CID-bb01a1bba579. This can be abused to perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation to root. In particular, there is a corner case where the off
    reg causes a masking direction change, which then results in an incorrect final aux->alu_limit.
    (CVE-2021-33200)

  - The io_uring subsystem in the Linux kernel allowed the MAX_RW_COUNT limit to be bypassed in the
    PROVIDE_BUFFERS operation, which led to negative values being usedin mem_rw when reading /proc//mem.
    This could be used to create a heap overflow leading to arbitrary code execution in the kernel. It was
    addressed via commit d1f82808877b (io_uring: truncate lengths larger than MAX_RW_COUNT on provide
    buffers) (v5.13-rc1) and backported to the stable kernels in v5.12.4, v5.11.21, and v5.10.37. It was
    introduced in ddf0322db79c (io_uring: add IORING_OP_PROVIDE_BUFFERS) (v5.7-rc1). (CVE-2021-3491)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186681");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/008950.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ec620b6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3491");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kernel-azure-5.3.18-18.50', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-azure-devel-5.3.18-18.50', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-devel-azure-5.3.18-18.50', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-source-azure-5.3.18-18.50', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-syms-azure-5.3.18-18.50', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-devel / kernel-devel-azure / etc');
}
