##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1669-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161225);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-27835",
    "CVE-2021-0707",
    "CVE-2021-4154",
    "CVE-2021-20292",
    "CVE-2021-20321",
    "CVE-2021-38208",
    "CVE-2022-0812",
    "CVE-2022-1158",
    "CVE-2022-1280",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1516",
    "CVE-2022-28356",
    "CVE-2022-28748",
    "CVE-2022-28893",
    "CVE-2022-29156"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1669-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:1669-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1669-1 advisory.

  - A use after free in the Linux kernel infiniband hfi1 driver in versions prior to 5.10-rc6 was found in the
    way user calls Ioctl after open dev file and fork. A local user could use this flaw to crash the system.
    (CVE-2020-27835)

  - In dma_buf_release of dma-buf.c, there is a possible memory corruption due to a use after free. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-155756045References:
    Upstream kernel (CVE-2021-0707)

  - There is a flaw reported in the Linux kernel in versions before 5.9 in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The issue
    results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker with a local account with a root privilege, can leverage this vulnerability to
    escalate privileges and execute code in the context of the kernel. (CVE-2021-20292)

  - A race condition accessing file object in the Linux kernel OverlayFS subsystem was found in the way users
    do rename in specific way with OverlayFS. A local user could use this flaw to crash the system.
    (CVE-2021-20321)

  - net/nfc/llcp_sock.c in the Linux kernel before 5.12.10 allows local unprivileged users to cause a denial
    of service (NULL pointer dereference and BUG) by making a getsockname call after a certain type of failure
    of a bind call. (CVE-2021-38208)

  - A use-after-free flaw was found in cgroup1_parse_param in kernel/cgroup/cgroup-v1.c in the Linux kernel's
    cgroup v1 parser. A local attacker with a user privilege could cause a privilege escalation by exploiting
    the fsconfig syscall parameter leading to a container breakout and a denial of service on the system.
    (CVE-2021-4154)

  - An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux
    Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.
    (CVE-2022-0812)

  - A flaw was found in KVM. When updating a guest's page table entry, vm_pgoff was improperly used as the
    offset to get the page's pfn. As vaddr and vm_pgoff are controllable by user-mode processes, this flaw
    allows unprivileged local users on the host to write outside the userspace region and potentially corrupt
    the kernel, resulting in a denial of service condition. (CVE-2022-1158)

  - A use-after-free vulnerability was found in drm_lease_held in drivers/gpu/drm/drm_lease.c in the Linux
    kernel due to a race problem. This flaw allows a local user privilege attacker to cause a denial of
    service (DoS) or a kernel information leak. (CVE-2022-1280)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - The root cause of this vulnerability is that the ioctl$DRM_IOCTL_MODE_DESTROY_DUMB can decrease refcount
    of *drm_vgem_gem_object *(created in *vgem_gem_dumb_create*) concurrently, and *vgem_gem_dumb_create *will
    access the freed drm_vgem_gem_object. (CVE-2022-1419)

  - A NULL pointer dereference flaw was found in the Linux kernel's X.25 set of standardized network protocols
    functionality in the way a user terminates their session using a simulated Ethernet card and continued
    usage of this connection. This flaw allows a local user to crash the system. (CVE-2022-1516)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - The SUNRPC subsystem in the Linux kernel through 5.17.2 can call xs_xprt_free before ensuring that sockets
    are in the intended state. (CVE-2022-28893)

  - drivers/infiniband/ulp/rtrs/rtrs-clt.c in the Linux kernel before 5.16.12 has a double free related to
    rtrs_clt_dev_release. (CVE-2022-29156)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1028340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199024");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-May/011018.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b69002cb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29156");
  script_set_attribute(attribute:"solution", value:
"Update the affected release-notes-sle_rt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29156");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-sle_rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'release-notes-sle_rt-15.3.20220422-150300.3.3.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'release-notes-sle_rt');
}
