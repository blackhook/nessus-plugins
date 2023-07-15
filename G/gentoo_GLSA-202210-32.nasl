#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-32.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166737);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id("CVE-2021-32765");

  script_name(english:"GLSA-202210-32 : hiredis, hiredis-py: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-32 (hiredis, hiredis-py: Multiple
Vulnerabilities)

  - Hiredis is a minimalistic C client library for the Redis database. In affected versions Hiredis is
    vulnurable to integer overflow if provided maliciously crafted or corrupted `RESP` `mult-bulk` protocol
    data. When parsing `multi-bulk` (array-like) replies, hiredis fails to check if `count *
    sizeof(redisReply*)` can be represented in `SIZE_MAX`. If it can not, and the `calloc()` call doesn't
    itself make this check, it would result in a short allocation and subsequent buffer overflow. Users of
    hiredis who are unable to update may set the [maxelements](https://github.com/redis/hiredis#reader-max-
    array-elements) context option to a value small enough that no overflow is possible. (CVE-2021-32765)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-32");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816318");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=873079");
  script_set_attribute(attribute:"solution", value:
"All hiredis users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-libs/hiredis-1.0.1
        
All hiredis-py users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-python/hiredis-2.0.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hiredis");
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
    'name' : 'dev-libs/hiredis',
    'unaffected' : make_list("ge 1.0.1", "lt 1.0.0"),
    'vulnerable' : make_list("lt 1.0.1")
  },
  {
    'name' : 'dev-python/hiredis',
    'unaffected' : make_list("ge 2.0.0"),
    'vulnerable' : make_list("lt 2.0.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hiredis / hiredis-py');
}
