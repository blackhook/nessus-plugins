#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-22.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166726);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id(
    "CVE-2021-3521",
    "CVE-2021-35937",
    "CVE-2021-35938",
    "CVE-2021-35939"
  );

  script_name(english:"GLSA-202210-22 : RPM: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-22 (RPM: Multiple Vulnerabilities)

  - There is a flaw in RPM's signature functionality. OpenPGP subkeys are associated with a primary key via a
    binding signature. RPM does not check the binding signature of subkeys prior to importing them. If an
    attacker is able to add or socially engineer another party to add a malicious subkey to a legitimate
    public key, RPM could wrongly trust a malicious signature. The greatest impact of this flaw is to data
    integrity. To exploit this flaw, an attacker must either compromise an RPM repository or convince an
    administrator to install an untrusted RPM or public key. It is strongly recommended to only use RPMs and
    public keys from trusted sources. (CVE-2021-3521)

  - A race condition vulnerability was found in rpm. A local unprivileged user could use this flaw to bypass
    the checks that were introduced in response to CVE-2017-7500 and CVE-2017-7501, potentially gaining root
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-35937)

  - A symbolic link issue was found in rpm. It occurs when rpm sets the desired permissions and credentials
    after installing a file. A local unprivileged user could use this flaw to exchange the original file with
    a symbolic link to a security-critical file and escalate their privileges on the system. The highest
    threat from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2021-35938)

  - It was found that the fix for CVE-2017-7500 and CVE-2017-7501 was incomplete: the check was only
    implemented for the parent directory of the file to be created. A local unprivileged user who owns another
    ancestor directory could potentially use this flaw to gain root privileges. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2021-35939)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-22");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830380");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866716");
  script_set_attribute(attribute:"solution", value:
"All RPM users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-arch/rpm-4.18.0");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3521");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-35939");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rpm");
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
    'name' : 'app-arch/rpm',
    'unaffected' : make_list("ge 4.18.0", "lt 4.0.0"),
    'vulnerable' : make_list("lt 4.18.0")
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
    severity   : SECURITY_NOTE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'RPM');
}
