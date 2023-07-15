#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202212-03.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(168907);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/18");

  script_cve_id(
    "CVE-2022-21620",
    "CVE-2022-21621",
    "CVE-2022-21627",
    "CVE-2022-39421",
    "CVE-2022-39422",
    "CVE-2022-39423",
    "CVE-2022-39424",
    "CVE-2022-39425",
    "CVE-2022-39426"
  );

  script_name(english:"GLSA-202212-03 : Oracle VirtualBox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202212-03 (Oracle VirtualBox: Multiple
Vulnerabilities)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.40. Difficult to exploit vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in takeover of
    Oracle VM VirtualBox. (CVE-2022-21620)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.40. Easily exploitable vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox.
    (CVE-2022-21621)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.40. Easily exploitable vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. (CVE-2022-21627)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.40. Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. Note: This vulnerability
    applies to Windows systems only. (CVE-2022-39421)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.38. Difficult to exploit vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in takeover of
    Oracle VM VirtualBox. (CVE-2022-39422)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.38. Easily exploitable vulnerability allows high privileged
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM
    VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle VM VirtualBox accessible data. (CVE-2022-39423)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are Prior to 6.1.40. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via VRDP to compromise Oracle VM VirtualBox. Successful attacks of this
    vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2022-39424, CVE-2022-39425,
    CVE-2022-39426)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202212-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=877601");
  script_set_attribute(attribute:"solution", value:
"All Oracle VirtualBox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/virtualbox-6.1.40
        
All Oracle VirtualBox modules users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/virtualbox-modules-6.1.40");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'name' : 'app-emulation/virtualbox',
    'unaffected' : make_list("ge 6.1.40"),
    'vulnerable' : make_list("lt 6.1.40")
  },
  {
    'name' : 'app-emulation/virtualbox-modules',
    'unaffected' : make_list("ge 6.1.40"),
    'vulnerable' : make_list("lt 6.1.40")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Oracle VirtualBox');
}
