#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-05.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(163842);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/04");

  script_cve_id(
    "CVE-2020-24368",
    "CVE-2022-24714",
    "CVE-2022-24715",
    "CVE-2022-24716"
  );

  script_name(english:"GLSA-202208-05 : Icinga Web 2: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-05 (Icinga Web 2: Multiple Vulnerabilities)

  - Icinga Icinga Web2 2.0.0 through 2.6.4, 2.7.4 and 2.8.2 has a Directory Traversal vulnerability which
    allows an attacker to access arbitrary files that are readable by the process running Icinga Web 2. This
    issue is fixed in Icinga Web 2 in v2.6.4, v2.7.4 and v2.8.2. (CVE-2020-24368)

  - Icinga Web 2 is an open source monitoring web interface, framework and command-line interface.
    Installations of Icinga 2 with the IDO writer enabled are affected. If you use service custom variables in
    role restrictions, and you regularly decommission service objects, users with said roles may still have
    access to a collection of content. Note that this only applies if a role has implicitly permitted access
    to hosts, due to permitted access to at least one of their services. If access to a host is permitted by
    other means, no sensible information has been disclosed to unauthorized users. This issue has been
    resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2. (CVE-2022-24714)

  - Icinga Web 2 is an open source monitoring web interface, framework and command-line interface.
    Authenticated users, with access to the configuration, can create SSH resource files in unintended
    directories, leading to the execution of arbitrary code. This issue has been resolved in versions 2.8.6,
    2.9.6 and 2.10 of Icinga Web 2. Users unable to upgrade should limit access to the Icinga Web 2
    configuration. (CVE-2022-24715)

  - Icinga Web 2 is an open source monitoring web interface, framework and command-line interface.
    Unauthenticated users can leak the contents of files of the local system accessible to the web-server
    user, including `icingaweb2` configuration files with database credentials. This issue has been resolved
    in versions 2.9.6 and 2.10 of Icinga Web 2. Database credentials should be rotated. (CVE-2022-24716)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-05");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=738024");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834802");
  script_set_attribute(attribute:"solution", value:
"All Icinga Web 2 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-apps/icingaweb2-2.9.6");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icingaweb2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-apps/icingaweb2",
    'unaffected' : make_list("ge 2.9.6"),
    'vulnerable' : make_list("lt 2.9.6")
  }
];

foreach package( packages ) {
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
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Icinga Web 2");
}
