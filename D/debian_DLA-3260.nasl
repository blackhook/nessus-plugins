#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3260. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169694);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_cve_id("CVE-2021-21366", "CVE-2022-39299", "CVE-2022-39353");

  script_name(english:"Debian DLA-3260-1 : node-xmldom - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3260 advisory.

  - xmldom is a pure JavaScript W3C standard-based (XML DOM Level 2 Core) DOMParser and XMLSerializer module.
    xmldom versions 0.4.0 and older do not correctly preserve system identifiers, FPIs or namespaces when
    repeatedly parsing and serializing maliciously crafted documents. This may lead to unexpected syntactic
    changes during XML processing in some downstream applications. This is fixed in version 0.5.0. As a
    workaround downstream applications can validate the input and reject the maliciously crafted documents.
    (CVE-2021-21366)

  - Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A
    remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful
    attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on
    the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if
    generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or
    newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you
    cannot upgrade, disabling SAML authentication may be done as a workaround. (CVE-2022-39299)

  - xmldom is a pure JavaScript W3C standard-based (XML DOM Level 2 Core) `DOMParser` and `XMLSerializer`
    module. xmldom parses XML that is not well-formed because it contains multiple top level elements, and
    adds all root nodes to the `childNodes` collection of the `Document`, without reporting any error or
    throwing. This breaks the assumption that there is only a single root node in the tree, which led to
    issuance of CVE-2022-39299 as it is a potential issue for dependents. Update to @xmldom/xmldom@~0.7.7,
    @xmldom/xmldom@~0.8.4 (dist-tag latest) or @xmldom/xmldom@>=0.9.0-beta.4 (dist-tag next). As a workaround,
    please one of the following approaches depending on your use case: instead of searching for elements in
    the whole DOM, only search in the `documentElement`or reject a document with a document that has more then
    1 `childNode`. (CVE-2022-39353)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1024736");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/node-xmldom");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21366");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39353");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/node-xmldom");
  script_set_attribute(attribute:"solution", value:
"Upgrade the node-xmldom packages.

For Debian 10 buster, these problems have been fixed in version 0.1.27+ds-1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21366");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-xmldom");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'node-xmldom', 'reference': '0.1.27+ds-1+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'node-xmldom');
}
