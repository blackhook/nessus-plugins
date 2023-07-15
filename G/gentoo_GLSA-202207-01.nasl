#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202207-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(163698);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/02");

  script_cve_id(
    "CVE-2020-25594",
    "CVE-2021-3024",
    "CVE-2021-3282",
    "CVE-2021-27668",
    "CVE-2021-32923",
    "CVE-2021-37219",
    "CVE-2021-38553",
    "CVE-2021-38554",
    "CVE-2021-41802",
    "CVE-2021-43998",
    "CVE-2021-45042",
    "CVE-2022-25243",
    "CVE-2022-30689"
  );

  script_name(english:"GLSA-202207-01 : HashiCorp Vault: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202207-01 (HashiCorp Vault: Multiple Vulnerabilities)

  - HashiCorp Vault and Vault Enterprise allowed for enumeration of Secrets Engine mount paths via
    unauthenticated HTTP requests. Fixed in 1.6.2 & 1.5.7. (CVE-2020-25594)

  - HashiCorp Vault Enterprise 0.9.2 through 1.6.2 allowed the read of license metadata from DR secondaries
    without authentication. Fixed in 1.6.3. (CVE-2021-27668)

  - HashiCorp Vault and Vault Enterprise disclosed the internal IP address of the Vault node when responding
    to some invalid, unauthenticated HTTP requests. Fixed in 1.6.2 & 1.5.7. (CVE-2021-3024)

  - HashiCorp Vault Enterprise 1.6.0 & 1.6.1 allowed the `remove-peer` raft operator command to be executed
    against DR secondaries without authentication. Fixed in 1.6.2. (CVE-2021-3282)

  - HashiCorp Vault and Vault Enterprise allowed the renewal of nearly-expired token leases and dynamic secret
    leases (specifically, those within 1 second of their maximum TTL), which caused them to be incorrectly
    treated as non-expiring during subsequent use. Fixed in 1.5.9, 1.6.5, and 1.7.2. (CVE-2021-32923)

  - HashiCorp Consul and Consul Enterprise 1.10.1 Raft RPC layer allows non-server agents with a valid
    certificate signed by the same CA to access server-only functionality, enabling privilege escalation.
    Fixed in 1.8.15, 1.9.9 and 1.10.2. (CVE-2021-37219)

  - HashiCorp Vault and Vault Enterprise 1.4.0 through 1.7.3 initialized an underlying database file
    associated with the Integrated Storage feature with excessively broad filesystem permissions. Fixed in
    Vault and Vault Enterprise 1.8.0. (CVE-2021-38553)

  - HashiCorp Vault and Vault Enterprise's UI erroneously cached and exposed user-viewed secrets between
    sessions in a single shared browser. Fixed in 1.8.0 and pending 1.7.4 / 1.6.6 releases. (CVE-2021-38554)

  - HashiCorp Vault and Vault Enterprise through 1.7.4 and 1.8.3 allowed a user with write permission to an
    entity alias ID sharing a mount accessor with another user to acquire this other user's policies by
    merging their identities. Fixed in Vault and Vault Enterprise 1.7.5 and 1.8.4. (CVE-2021-41802)

  - HashiCorp Vault and Vault Enterprise 0.11.0 up to 1.7.5 and 1.8.4 templated ACL policies would always
    match the first-created entity alias if multiple entity aliases exist for a specified entity and mount
    combination, potentially resulting in incorrect policy enforcement. Fixed in Vault and Vault Enterprise
    1.7.6, 1.8.5, and 1.9.0. (CVE-2021-43998)

  - In HashiCorp Vault and Vault Enterprise before 1.7.7, 1.8.x before 1.8.6, and 1.9.x before 1.9.1, clusters
    using the Integrated Storage backend allowed an authenticated user (with write permissions to a kv secrets
    engine) to cause a panic and denial of service of the storage backend. The earliest affected version is
    1.4.0. (CVE-2021-45042)

  - Vault and Vault Enterprise 1.8.0 through 1.8.8, and 1.9.3 allowed the PKI secrets engine under certain
    configurations to issue wildcard certificates to authorized users for a specified domain, even if the PKI
    role policy attribute allow_subdomains is set to false. Fixed in Vault Enterprise 1.8.9 and 1.9.4.
    (CVE-2022-25243)

  - HashiCorp Vault and Vault Enterprise from 1.10.0 to 1.10.2 did not correctly configure and enforce MFA on
    login after server restarts. This affects the Login MFA feature introduced in Vault and Vault Enterprise
    1.10.0 and does not affect the separate Enterprise MFA feature set. Fixed in 1.10.3. (CVE-2022-30689)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202207-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=768312");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=797244");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=808093");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=817269");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=827945");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829493");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835070");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=845405");
  script_set_attribute(attribute:"solution", value:
"All HashiCorp Vault users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-admin/vault-1.10.3");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vault");
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
    'name' : "app-admin/vault",
    'unaffected' : make_list("ge 1.10.3"),
    'vulnerable' : make_list("lt 1.10.3")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "HashiCorp Vault");
}
