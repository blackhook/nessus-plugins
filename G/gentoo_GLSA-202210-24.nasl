#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-24.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166721);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id(
    "CVE-2021-41159",
    "CVE-2021-41160",
    "CVE-2022-24882",
    "CVE-2022-24883",
    "CVE-2022-39282",
    "CVE-2022-39283"
  );

  script_name(english:"GLSA-202210-24 : FreeRDP: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-24 (FreeRDP: Multiple Vulnerabilities)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    All FreeRDP clients prior to version 2.4.1 using gateway connections (`/gt:rpc`) fail to validate input
    data. A malicious gateway might allow client memory to be written out of bounds. This issue has been
    resolved in version 2.4.1. If you are unable to update then use `/gt:http` rather than /gt:rdp connections
    if possible or use a direct connection without a gateway. (CVE-2021-41159)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions a malicious server might trigger out of bound writes in a connected client.
    Connections using GDI or SurfaceCommands to send graphics updates to the client might send `0`
    width/height or out of bound rectangles to trigger out of bound writes. With `0` width or heigth the
    memory allocation will be `0` but the missing bounds checks allow writing to the pointer at this (not
    allocated) region. This issue has been patched in FreeRDP 2.4.1. (CVE-2021-41160)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP). In versions prior to 2.7.0, NT LAN
    Manager (NTLM) authentication does not properly abort when someone provides and empty password value. This
    issue affects FreeRDP based RDP Server implementations. RDP clients are not affected. The vulnerability is
    patched in FreeRDP 2.7.0. There are currently no known workarounds. (CVE-2022-24882)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP). Prior to version 2.7.0, server side
    authentication against a `SAM` file might be successful for invalid credentials if the server has
    configured an invalid `SAM` file path. FreeRDP based clients are not affected. RDP server implementations
    using FreeRDP to authenticate against a `SAM` file are affected. Version 2.7.0 contains a fix for this
    issue. As a workaround, use custom authentication via `HashCallback` and/or ensure the `SAM` database path
    configured is valid and the application has file handles left. (CVE-2022-24883)

  - FreeRDP is a free remote desktop protocol library and clients. FreeRDP based clients on unix systems using
    `/parallel` command line switch might read uninitialized data and send it to the server the client is
    currently connected to. FreeRDP based server implementations are not affected. Please upgrade to 2.8.1
    where this issue is patched. If unable to upgrade, do not use parallel port redirection (`/parallel`
    command line switch) as a workaround. (CVE-2022-39282)

  - FreeRDP is a free remote desktop protocol library and clients. All FreeRDP based clients when using the
    `/video` command line switch might read uninitialized data, decode it as audio/video and display the
    result. FreeRDP based server implementations are not affected. This issue has been patched in version
    2.8.1. If you cannot upgrade do not use the `/video` switch. (CVE-2022-39283)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-24");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=819534");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=842231");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876905");
  script_set_attribute(attribute:"solution", value:
"All FreeRDP users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/freerdp-2.8.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24883");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'net-misc/freerdp',
    'unaffected' : make_list("ge 2.8.1", "lt 2.0.0"),
    'vulnerable' : make_list("lt 2.8.1")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'FreeRDP');
}
