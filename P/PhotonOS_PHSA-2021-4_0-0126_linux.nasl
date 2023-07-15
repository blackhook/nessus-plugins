#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-4.0-0126. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155326);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/15");

  script_cve_id(
    "CVE-2020-16119",
    "CVE-2021-40490",
    "CVE-2021-41073",
    "CVE-2021-41864",
    "CVE-2021-42252"
  );

  script_name(english:"Photon OS 4.0: Linux PHSA-2021-4.0-0126");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.

  - loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain
    privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by
    using /proc/<pid>/maps for exploitation. (CVE-2021-41073)

  - Use-after-free vulnerability in the Linux kernel exploitable by a local attacker due to reuse of a DCCP
    socket with an attached dccps_hc_tx_ccid object as a listener after being released. Fixed in Ubuntu Linux
    kernel 5.4.0-51.56, 5.3.0-68.63, 4.15.0-121.123, 4.4.0-193.224, 3.13.0.182.191 and 3.2.0-149.196.
    (CVE-2020-16119)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel through 5.14.9 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - An issue was discovered in aspeed_lpc_ctrl_mmap in drivers/soc/aspeed/aspeed-lpc-ctrl.c in the Linux
    kernel before 5.14.6. Local attackers able to access the Aspeed LPC control interface could overwrite
    memory in the kernel and potentially execute privileges, aka CID-b49a0e69a7b1. This occurs because a
    certain comparison uses values that are not memory sizes. (CVE-2021-42252)

");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-4.0-0126.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:4.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 4\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 4.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', reference:'linux-api-headers-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-devel-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-docs-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-drivers-gpu-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-oprofile-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-sound-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-devel-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-docs-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-gpu-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-intel-sgx-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-sound-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-devel-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-docs-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-oprofile-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-python3-perf-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-devel-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-docs-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-devel-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-docs-5.10.75-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-tools-5.10.75-1.ph4')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux');
}
