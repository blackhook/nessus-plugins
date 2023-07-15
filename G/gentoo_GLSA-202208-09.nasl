#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(163985);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/10");

  script_cve_id(
    "CVE-2020-25201",
    "CVE-2020-25864",
    "CVE-2020-28053",
    "CVE-2021-28156",
    "CVE-2021-32574",
    "CVE-2021-36213",
    "CVE-2021-38698",
    "CVE-2022-24687",
    "CVE-2022-29153"
  );

  script_name(english:"GLSA-202208-09 : HashiCorp Consul: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-09 (HashiCorp Consul: Multiple
Vulnerabilities)

  - HashiCorp Consul Enterprise version 1.7.0 up to 1.8.4 includes a namespace replication bug which can be
    triggered to cause denial of service via infinite Raft writes. Fixed in 1.7.9 and 1.8.5. (CVE-2020-25201)

  - HashiCorp Consul and Consul Enterprise up to version 1.9.4 key-value (KV) raw mode was vulnerable to
    cross-site scripting. Fixed in 1.9.5, 1.8.10 and 1.7.14. (CVE-2020-25864)

  - HashiCorp Consul and Consul Enterprise 1.2.0 up to 1.8.5 allowed operators with operator:read ACL
    permissions to read the Connect CA private key configuration. Fixed in 1.6.10, 1.7.10, and 1.8.6.
    (CVE-2020-28053)

  - HashiCorp Consul Enterprise version 1.8.0 up to 1.9.4 audit log can be bypassed by specifically crafted
    HTTP events. Fixed in 1.9.5, and 1.8.10. (CVE-2021-28156)

  - HashiCorp Consul and Consul Enterprise 1.3.0 through 1.10.0 Envoy proxy TLS configuration does not
    validate destination service identity in the encoded subject alternative name. Fixed in 1.8.14, 1.9.8, and
    1.10.1. (CVE-2021-32574)

  - HashiCorp Consul and Consul Enterprise 1.9.0 through 1.10.0 default deny policy with a single L7
    application-aware intention deny action cancels out, causing the intention to incorrectly fail open,
    allowing L4 traffic. Fixed in 1.9.8 and 1.10.1. (CVE-2021-36213)

  - HashiCorp Consul and Consul Enterprise 1.10.1 Txn.Apply endpoint allowed services to register proxies for
    other services, enabling access to service traffic. Fixed in 1.8.15, 1.9.9 and 1.10.2. (CVE-2021-38698)

  - HashiCorp Consul and Consul Enterprise 1.8.0 through 1.9.14, 1.10.7, and 1.11.2 has Uncontrolled Resource
    Consumption. (CVE-2022-24687)

  - HashiCorp Consul and Consul Enterprise through 2022-04-12 allow SSRF. (CVE-2022-29153)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=760696");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=783483");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802522");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=812497");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834006");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838328");
  script_set_attribute(attribute:"solution", value:
"All HashiCorp Consul users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-admin/consul-1.9.17");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:consul");
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
    'name' : "app-admin/consul",
    'unaffected' : make_list("ge 1.9.17"),
    'vulnerable' : make_list("lt 1.9.17")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "HashiCorp Consul");
}
