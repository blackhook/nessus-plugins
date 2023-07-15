#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-25.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176193);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/21");

  script_cve_id(
    "CVE-2021-35368",
    "CVE-2022-39955",
    "CVE-2022-39956",
    "CVE-2022-39957",
    "CVE-2022-39958"
  );

  script_name(english:"GLSA-202305-25 : OWASP ModSecurity Core Rule Set: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-25 (OWASP ModSecurity Core Rule Set: Multiple
Vulnerabilities)

  - OWASP ModSecurity Core Rule Set 3.1.x before 3.1.2, 3.2.x before 3.2.1, and 3.3.x before 3.3.2 is affected
    by a Request Body Bypass via a trailing pathname. (CVE-2021-35368)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set bypass by submitting a
    specially crafted HTTP Content-Type header field that indicates multiple character encoding schemes. A
    vulnerable back-end can potentially be exploited by declaring multiple Content-Type charset names and
    therefore bypassing the configurable CRS Content-Type header charset allow list. An encoded payload can
    bypass CRS detection this way and may then be decoded by the backend. The legacy CRS versions 3.0.x and
    3.1.x are affected, as well as the currently supported versions 3.2.1 and 3.3.2. Integrators and users are
    advised to upgrade to 3.2.2 and 3.3.3 respectively. (CVE-2022-39955)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a partial rule set bypass for HTTP multipart
    requests by submitting a payload that uses a character encoding scheme via the Content-Type or the
    deprecated Content-Transfer-Encoding multipart MIME header fields that will not be decoded and inspected
    by the web application firewall engine and the rule set. The multipart payload will therefore bypass
    detection. A vulnerable backend that supports these encoding schemes can potentially be exploited. The
    legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and
    3.3.2. Integrators and users are advised upgrade to 3.2.2 and 3.3.3 respectively. The mitigation against
    these vulnerabilities depends on the installation of the latest ModSecurity version (v2.9.6 / v3.0.8).
    (CVE-2022-39956)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass. A client can issue an
    HTTP Accept header field containing an optional charset parameter in order to receive the response in an
    encoded form. Depending on the charset, this response can not be decoded by the web application
    firewall. A restricted resource, access to which would ordinarily be detected, may therefore bypass
    detection. The legacy CRS versions 3.0.x and 3.1.x are affected, as well as the currently supported
    versions 3.2.1 and 3.3.2. Integrators and users are advised to upgrade to 3.2.2 and 3.3.3 respectively.
    (CVE-2022-39957)

  - The OWASP ModSecurity Core Rule Set (CRS) is affected by a response body bypass to sequentially exfiltrate
    small and undetectable sections of data by repeatedly submitting an HTTP Range header field with a small
    byte range. A restricted resource, access to which would ordinarily be detected, may be exfiltrated from
    the backend, despite being protected by a web application firewall that uses CRS. Short subsections of a
    restricted resource may bypass pattern matching techniques and allow undetected access. The legacy CRS
    versions 3.0.x and 3.1.x are affected, as well as the currently supported versions 3.2.1 and 3.3.2.
    Integrators and users are advised to upgrade to 3.2.2 and 3.3.3 respectively and to configure a CRS
    paranoia level of 3 or higher. (CVE-2022-39958)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-25");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=822003");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=872077");
  script_set_attribute(attribute:"solution", value:
"All OWASP ModSecurity Core Rule Set users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-apache/modsecurity-crs-3.3.4");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35368");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39956");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:modsecurity-crs");
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
    'name' : 'www-apache/modsecurity-crs',
    'unaffected' : make_list("ge 3.3.4"),
    'vulnerable' : make_list("lt 3.3.4")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OWASP ModSecurity Core Rule Set');
}
