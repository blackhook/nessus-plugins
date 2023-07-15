#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-24.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165540);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/29");

  script_cve_id(
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-23852",
    "CVE-2022-23990",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25313",
    "CVE-2022-25314",
    "CVE-2022-25315",
    "CVE-2022-40674"
  );

  script_name(english:"GLSA-202209-24 : Expat: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-24 (Expat: Multiple Vulnerabilities)

  - In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in
    xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).
    (CVE-2021-45960)

  - In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for
    m_groupSize. (CVE-2021-46143)

  - addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22822)

  - build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22823)

  - defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22824)

  - lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22825)

  - nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22826)

  - storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22827)

  - Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with
    a nonzero XML_CONTEXT_BYTES. (CVE-2022-23852)

  - Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function. (CVE-2022-23990)

  - xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks
    for whether a UTF-8 character is valid in a certain context. (CVE-2022-25235)

  - xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters
    into namespace URIs. (CVE-2022-25236)

  - In Expat (aka libexpat) before 2.4.5, an attacker can trigger stack exhaustion in build_model via a large
    nesting depth in the DTD element. (CVE-2022-25313)

  - In Expat (aka libexpat) before 2.4.5, there is an integer overflow in copyString. (CVE-2022-25314)

  - In Expat (aka libexpat) before 2.4.5, there is an integer overflow in storeRawNames. (CVE-2022-25315)

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-24");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=791703");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830422");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831918");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833431");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=870097");
  script_set_attribute(attribute:"solution", value:
"All Expat users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-libs/expat-2.4.9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-40674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:expat");
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
    'name' : "dev-libs/expat",
    'unaffected' : make_list("ge 2.4.9", "lt 2.0.0"),
    'vulnerable' : make_list("lt 2.4.9")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Expat");
}
