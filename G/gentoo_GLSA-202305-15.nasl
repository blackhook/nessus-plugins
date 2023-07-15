#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-15.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175054);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id("CVE-2021-3997", "CVE-2022-3821");

  script_name(english:"GLSA-202305-15 : systemd: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-15 (systemd: Multiple Vulnerabilities)

  - A flaw was found in systemd. An uncontrolled recursion in systemd-tmpfiles may lead to a denial of service
    at boot time when too many nested directories are created in /tmp. (CVE-2021-3997)

  - An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An
    attacker could supply specific values for time and accuracy that leads to buffer overrun in
    format_timespan(), leading to a Denial of Service. (CVE-2022-3821)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-15");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830967");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=880547");
  script_set_attribute(attribute:"solution", value:
"All systemd users should upgrade to the latest version:            # emerge --sync           # emerge --ask --oneshot
--verbose >=sys-apps/systemd-251.3          All systemd-utils users should upgrade to the latest version:            #
emerge --sync           # emerge --ask --oneshot --verbose >=sys-apps/systemd-utils-251.3          Gentoo has
discontinued support for sys-apps/systemd-tmpfiles, sys-boot/systemd-boot, and sys-fs/udev. See the 2022-04-19-systemd-
utils news item. Users should unmerge it in favor of sys-apps/systemd-utils on non-systemd systems:            # emerge
--ask --depclean --verbose sys-apps/systemd-tmpfiles sys-boot/systemd-boot sys-fs/udev           # emerge --ask
--verbose --oneshot >=sys-apps/systemd-utils-251.3");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:systemd-utils");
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
    'name' : 'sys-apps/systemd',
    'unaffected' : make_list("ge 251.3"),
    'vulnerable' : make_list("lt 251.3")
  },
  {
    'name' : 'sys-apps/systemd-utils',
    'unaffected' : make_list("ge 251.3"),
    'vulnerable' : make_list("lt 251.3")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd');
}
