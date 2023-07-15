#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-30.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176467);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id(
    "CVE-2021-4008",
    "CVE-2021-4009",
    "CVE-2021-4010",
    "CVE-2021-4011",
    "CVE-2022-3550",
    "CVE-2022-3551",
    "CVE-2022-3553",
    "CVE-2022-4283",
    "CVE-2022-46283",
    "CVE-2022-46340",
    "CVE-2022-46341",
    "CVE-2022-46342",
    "CVE-2022-46343",
    "CVE-2022-46344",
    "CVE-2023-0494",
    "CVE-2023-1393"
  );

  script_name(english:"GLSA-202305-30 : X.Org X server, XWayland: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-30 (X.Org X server, XWayland: Multiple
Vulnerabilities)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcRenderCompositeGlyphs function. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-4008)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcXFixesCreatePointerBarrier function. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-4009)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SProcScreenSaverSuspend function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4010)

  - A flaw was found in xorg-x11-server in versions before 21.1.2 and before 1.20.14. An out-of-bounds access
    can occur in the SwapCreateRegister function. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-4011)

  - A vulnerability classified as critical was found in X.org Server. Affected by this vulnerability is the
    function _GetCountedString of the file xkb/xkb.c. The manipulation leads to buffer overflow. It is
    recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is
    VDB-211051. (CVE-2022-3550)

  - A vulnerability, which was classified as problematic, has been found in X.org Server. Affected by this
    issue is the function ProcXkbGetKbdByName of the file xkb/xkb.c. The manipulation leads to memory leak. It
    is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211052.
    (CVE-2022-3551)

  - A vulnerability, which was classified as problematic, was found in X.org Server. This affects an unknown
    part of the file hw/xquartz/X11Controller.m of the component xquartz. The manipulation leads to denial of
    service. It is recommended to apply a patch to fix this issue. The identifier VDB-211053 was assigned to
    this vulnerability. (CVE-2022-3553)

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

  - A flaw was found in X.Org Server Overlay Window. A Use-After-Free may lead to local privilege escalation.
    If a client explicitly destroys the compositor overlay window (aka COW), the Xserver would leave a
    dangling pointer to that window in the CompScreen structure, which will trigger a use-after-free later.
    (CVE-2023-1393)

  -  Please review the referenced CVE identifiers for details.  (CVE-2022-46283)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-30");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829208");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=877459");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=885825");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=893438");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903547");
  script_set_attribute(attribute:"solution", value:
"All X.Org X server users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-base/xorg-server-21.1.8
        
All XWayland users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-base/xwayland-23.1.1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4011");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46344");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xwayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'x11-base/xorg-server',
    'unaffected' : make_list("ge 21.1.8"),
    'vulnerable' : make_list("lt 21.1.8")
  },
  {
    'name' : 'x11-base/xwayland',
    'unaffected' : make_list("ge 23.1.1"),
    'vulnerable' : make_list("lt 23.1.1")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'X.Org X server / XWayland');
}
