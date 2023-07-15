#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202301-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(169834);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2022-21712", "CVE-2022-21716", "CVE-2022-39348");

  script_name(english:"GLSA-202301-02 : Twisted: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202301-02 (Twisted: Multiple Vulnerabilities)

  - twisted is an event-driven networking engine written in Python. In affected versions twisted exposes
    cookies and authorization headers when following cross-origin redirects. This issue is present in the
    `twited.web.RedirectAgent` and `twisted.web. BrowserLikeRedirectAgent` functions. Users are advised to
    upgrade. There are no known workarounds. (CVE-2022-21712)

  - Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0,
    Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH
    version identifier. This ends up with a buffer using all the available memory. The attach is a simple as
    `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known
    workarounds. (CVE-2022-21716)

  - Twisted is an event-based framework for internet applications. Started with version 0.9.4, when the host
    header does not match a configured host `twisted.web.vhost.NameVirtualHost` will return a `NoResource`
    resource which renders the Host header unescaped into the 404 response allowing HTML and script injection.
    In practice this should be very difficult to exploit as being able to modify the Host header of a normal
    HTTP request implies that one is already in a privileged position. This issue was fixed in version
    22.10.0rc1. There are no known workarounds. (CVE-2022-39348)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202301-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832875");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834542");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878499");
  script_set_attribute(attribute:"solution", value:
"All Twisted users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-python/twisted-22.10.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:twisted");
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
    'name' : 'dev-python/twisted',
    'unaffected' : make_list("ge 22.10.0"),
    'vulnerable' : make_list("lt 22.10.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Twisted');
}
