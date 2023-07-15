#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-34.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166768);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42930",
    "CVE-2022-42931",
    "CVE-2022-42932"
  );
  script_xref(name:"IAVA", value:"2023-A-0132-S");

  script_name(english:"GLSA-202210-34 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-34 (Mozilla Firefox: Multiple Vulnerabilities)

  - A same-origin policy violation could have allowed the theft of cross-origin URL entries, leaking the
    result of a redirect, via <code>performance.getEntries()</code>.  (CVE-2022-42927)

  - Certain types of allocations were missing annotations that, if the Garbage Collector was in a specific
    state, could have lead to memory corruption and a potentially exploitable crash.  (CVE-2022-42928)

  - If a website called <code>window.print()</code> in a particular way, it could cause a denial of service of
    the browser, which may persist beyond browser restart depending on the user's session restore settings.
    (CVE-2022-42929)

  - If two Workers were simultaneously initializing their CacheStorage, a data race could have occurred in the
    <code>ThirdPartyUtil</code> component.  (CVE-2022-42930)

  - Logins saved by Firefox should be managed by the Password Manager component which uses encryption to save
    files on-disk. Instead, the username (not password) was saved by the Form Manager to an unencrypted file
    on disk.  (CVE-2022-42931)

  - Mozilla developers Ashley Hale and the Mozilla Fuzzing Team reported memory safety bugs present in
    Thunderbird 102.3. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code.  (CVE-2022-42932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-34");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=877773");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox ESR users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-102.4.0
        
All Mozilla Firefox ESR binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-102.4.0
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-106.0
        
All Mozilla Firefox binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-106.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42932");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 102.4.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.4.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 106.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 106.0", "gt 103.0.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 102.4.0", "lt 102.0.0"),
    'vulnerable' : make_list("lt 102.4.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 106.0", "lt 103.0.0"),
    'vulnerable' : make_list("lt 106.0", "gt 103.0.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
