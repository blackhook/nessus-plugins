#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202211-04.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(168040);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/22");

  script_cve_id(
    "CVE-2021-3677",
    "CVE-2021-23214",
    "CVE-2021-23222",
    "CVE-2021-32027",
    "CVE-2021-32028",
    "CVE-2022-1552",
    "CVE-2022-2625"
  );

  script_name(english:"GLSA-202211-04 : PostgreSQL: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202211-04 (PostgreSQL: Multiple Vulnerabilities)

  - When the server is configured to use trust authentication with a clientcert requirement or to use cert
    authentication, a man-in-the-middle attacker can inject arbitrary SQL queries when a connection is first
    established, despite the use of SSL certificate verification and encryption. (CVE-2021-23214)

  - A man-in-the-middle attacker can inject false responses to the client's first few queries, despite the use
    of SSL certificate verification and encryption. (CVE-2021-23222)

  - A flaw was found in postgresql in versions before 13.3, before 12.7, before 11.12, before 10.17 and before
    9.6.22. While modifying certain SQL array values, missing bounds checks let authenticated database users
    write arbitrary bytes to a wide area of server memory. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-32027)

  - A flaw was found in postgresql. Using an INSERT ... ON CONFLICT ... DO UPDATE command on a purpose-crafted
    table, an authenticated database user could read arbitrary bytes of server memory. The highest threat from
    this vulnerability is to data confidentiality. (CVE-2021-32028)

  - A flaw was found in postgresql. A purpose-crafted query can read arbitrary bytes of server memory. In the
    default configuration, any authenticated database user can complete this attack at will. The attack does
    not require the ability to create objects. If server settings include max_worker_processes=0, the known
    versions of this attack are infeasible. However, undiscovered variants of the attack may be independent of
    that setting. (CVE-2021-3677)

  - A flaw was found in PostgreSQL. There is an issue with incomplete efforts to operate safely when a
    privileged user is maintaining another user's objects. The Autovacuum, REINDEX, CREATE INDEX, REFRESH
    MATERIALIZED VIEW, CLUSTER, and pg_amcheck commands activated relevant protections too late or not at all
    during the process. This flaw allows an attacker with permission to create non-temporary objects in at
    least one schema to execute arbitrary SQL functions under a superuser identity. (CVE-2022-1552)

  - A vulnerability was found in PostgreSQL. This attack requires permission to create non-temporary objects
    in at least one schema, the ability to lure or wait for an administrator to create or update an affected
    extension in that schema, and the ability to lure or wait for a victim to use the object targeted in
    CREATE OR REPLACE or CREATE IF NOT EXISTS. Given all three prerequisites, this flaw allows an attacker to
    run arbitrary code as the victim role, which may be a superuser. (CVE-2022-2625)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202211-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=793734");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=808984");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=823125");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=865255");
  script_set_attribute(attribute:"solution", value:
"All PostgreSQL 10.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-10.22:10
        
All PostgreSQL 11.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-11.17:11
        
All PostgreSQL 12.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-12.12:12
        
All PostgreSQL 13.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-13.8:13
        
All PostgreSQL 14.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-14.5:14");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32027");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql");
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
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 10.22", "lt 10.0.0"),
    'vulnerable' : make_list("lt 10.22")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 11.17", "lt 11.0.0"),
    'vulnerable' : make_list("lt 11.17")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 12.12", "lt 12.0.0"),
    'vulnerable' : make_list("lt 12.12")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 13.8", "lt 13.0.0"),
    'vulnerable' : make_list("lt 13.8")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 14.5", "lt 14.0.0"),
    'vulnerable' : make_list("lt 14.5")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'PostgreSQL');
}
