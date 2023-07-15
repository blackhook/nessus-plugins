#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-29.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164110);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

  script_cve_id("CVE-2020-26247", "CVE-2022-24836", "CVE-2022-29181");

  script_name(english:"GLSA-202208-29 : Nokogiri: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-29 (Nokogiri: Multiple Vulnerabilities)

  - Nokogiri is a Rubygem providing HTML, XML, SAX, and Reader parsers with XPath and CSS selector support. In
    Nokogiri before version 1.11.0.rc4 there is an XXE vulnerability. XML Schemas parsed by
    Nokogiri::XML::Schema are trusted by default, allowing external resources to be accessed over the network,
    potentially enabling XXE or SSRF attacks. This behavior is counter to the security policy followed by
    Nokogiri maintainers, which is to treat all input as untrusted by default whenever possible. This is fixed
    in Nokogiri version 1.11.0.rc4. (CVE-2020-26247)

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri `< v1.13.4` contains an inefficient
    regular expression that is susceptible to excessive backtracking when attempting to detect encoding in
    HTML documents. Users are advised to upgrade to Nokogiri `>= 1.13.4`. There are no known workarounds for
    this issue. (CVE-2022-24836)

  - Nokogiri is an open source XML and HTML library for Ruby. Nokogiri prior to version 1.13.6 does not type-
    check all inputs into the XML and HTML4 SAX parsers, allowing specially crafted untrusted inputs to cause
    illegal memory access errors (segfault) or reads from unrelated memory. Version 1.13.6 contains a patch
    for this issue. As a workaround, ensure the untrusted input is a `String` by calling `#to_s` or
    equivalent. (CVE-2022-29181)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-29");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=762685");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=837902");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=846623");
  script_set_attribute(attribute:"solution", value:
"All Nokogiri users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-ruby/nokogiri-1.13.6");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nokogiri");
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
    'name' : "dev-ruby/nokogiri",
    'unaffected' : make_list("ge 1.13.6"),
    'vulnerable' : make_list("lt 1.13.6")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Nokogiri");
}
