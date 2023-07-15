#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1609-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(173632);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2022-3523",
    "CVE-2022-38096",
    "CVE-2023-0461",
    "CVE-2023-0597",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1078",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-22995",
    "CVE-2023-22998",
    "CVE-2023-23000",
    "CVE-2023-23004",
    "CVE-2023-23559",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-28328"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1609-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:1609-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:1609-1 advisory.

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown
    function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211020. (CVE-2022-3523)

  - A NULL pointer dereference vulnerability was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_execbuf.c
    in GPU component of Linux kernel with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a
    local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).
    (CVE-2022-38096)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A flaw possibility of memory leak in the Linux kernel cpu_entry_area mapping of X86 CPU data to memory was
    found in the way user can guess location of exception stack(s) or other important data. A local user could
    use this flaw to get access to some important data with expected location in memory. (CVE-2023-0597)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - In the Linux kernel before 5.17, an error path in dwc3_qcom_acpi_register_core in
    drivers/usb/dwc3/dwc3-qcom.c lacks certain platform_device_put and kfree calls. (CVE-2023-22995)

  - In the Linux kernel before 6.0.3, drivers/gpu/drm/virtio/virtgpu_object.c misinterprets the
    drm_gem_shmem_get_sg_table return value (expects it to be NULL in the error case, whereas it is actually
    an error pointer). (CVE-2023-22998)

  - In the Linux kernel before 5.17, drivers/phy/tegra/xusb.c mishandles the tegra_xusb_find_port_node return
    value. Callers expect NULL in the error case, but an error pointer is used. (CVE-2023-23000)

  - In the Linux kernel before 5.19, drivers/gpu/drm/arm/malidp_planes.c misinterprets the get_sg_table return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23004)

  - In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an
    integer overflow in an addition. (CVE-2023-23559)

  - The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a
    crafted USB device because the LED controllers remain registered for too long. (CVE-2023-25012)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209504");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/014197.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d67bc0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28328");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_15_18-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-rt-5.14.21-150400.15.18.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-devel-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-rt-5.14.21-150400.15.18.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150400.15.18.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_15_18-rt-1-150400.1.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
