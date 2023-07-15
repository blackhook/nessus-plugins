#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:2805. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176148);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/20");

  script_cve_id(
    "CVE-2022-3550",
    "CVE-2022-3551",
    "CVE-2022-4283",
    "CVE-2022-46340",
    "CVE-2022-46341",
    "CVE-2022-46342",
    "CVE-2022-46343",
    "CVE-2022-46344",
    "CVE-2023-0494"
  );
  script_xref(name:"RHSA", value:"2023:2805");

  script_name(english:"CentOS 8 : xorg-x11-server-Xwayland (CESA-2023:2805)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
CESA-2023:2805 advisory.

  - A vulnerability classified as critical was found in X.org Server. Affected by this vulnerability is the
    function _GetCountedString of the file xkb/xkb.c. The manipulation leads to buffer overflow. It is
    recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is
    VDB-211051. (CVE-2022-3550)

  - A vulnerability, which was classified as problematic, has been found in X.org Server. Affected by this
    issue is the function ProcXkbGetKbdByName of the file xkb/xkb.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211052.
    (CVE-2022-3551)

  - A vulnerability was found in X.Org. This security flaw occurs because the XkbCopyNames function left a
    dangling pointer to freed memory, resulting in out-of-bounds memory access on subsequent XkbGetKbdByName
    requests.. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-4283)

  - A vulnerability was found in X.Org. This security flaw occurs becuase the swap handler for the
    XTestFakeInput request of the XTest extension may corrupt the stack if GenericEvents with lengths larger
    than 32 bytes are sent through a the XTestFakeInput request. This issue can lead to local privileges
    elevation on systems where the X server is running privileged and remote code execution for ssh X
    forwarding sessions. This issue does not affect systems where client and server use the same byte order.
    (CVE-2022-46340)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIPassiveUngrab
    request accesses out-of-bounds memory when invoked with a high keycode or button code. This issue can lead
    to local privileges elevation on systems where the X server is running privileged and remote code
    execution for ssh X forwarding sessions. (CVE-2022-46341)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    XvdiSelectVideoNotify request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X se (CVE-2022-46342)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the
    ScreenSaverSetAttributes request may write to memory after it has been freed. This issue can lead to local
    privileges elevation on systems where the X server is running privileged and remote code execution for ssh
    X forwarding sessions. (CVE-2022-46343)

  - A vulnerability was found in X.Org. This security flaw occurs because the handler for the XIChangeProperty
    request has a length-validation issues, resulting in out-of-bounds memory reads and potential information
    disclosure. This issue can lead to local privileges elevation on systems where the X server is running
    privileged and remote code execution for ssh X forwarding sessions. (CVE-2022-46344)

  - A vulnerability was found in X.Org. This issue occurs due to a dangling pointer in DeepCopyPointerClasses
    that can be exploited by ProcXkbSetDeviceInfo() and ProcXkbGetDeviceInfo() to read and write into freed
    memory. This can lead to local privilege elevation on systems where the X server runs privileged and
    remote code execution for ssh X forwarding sessions. (CVE-2023-0494)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:2805");
  script_set_attribute(attribute:"solution", value:
"Update the affected xorg-x11-server-Xwayland package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'xorg-x11-server-Xwayland-21.1.3-10.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-21.1.3-10.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xorg-x11-server-Xwayland');
}
