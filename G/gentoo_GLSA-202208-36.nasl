#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-36.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164536);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2021-2145",
    "CVE-2021-2250",
    "CVE-2021-2264",
    "CVE-2021-2266",
    "CVE-2021-2279",
    "CVE-2021-2280",
    "CVE-2021-2281",
    "CVE-2021-2282",
    "CVE-2021-2283",
    "CVE-2021-2284",
    "CVE-2021-2285",
    "CVE-2021-2286",
    "CVE-2021-2287",
    "CVE-2021-2291",
    "CVE-2021-2296",
    "CVE-2021-2297",
    "CVE-2021-2306",
    "CVE-2021-2309",
    "CVE-2021-2310",
    "CVE-2021-2312",
    "CVE-2021-2409",
    "CVE-2021-2442",
    "CVE-2021-2443",
    "CVE-2021-2454",
    "CVE-2021-2475",
    "CVE-2021-35538",
    "CVE-2021-35540",
    "CVE-2021-35542",
    "CVE-2021-35545",
    "CVE-2022-21394",
    "CVE-2022-21465",
    "CVE-2022-21471",
    "CVE-2022-21487",
    "CVE-2022-21488",
    "CVE-2022-21554",
    "CVE-2022-21571"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"GLSA-202208-36 : Oracle VirtualBox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-36 (Oracle VirtualBox: Multiple
Vulnerabilities)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H). (CVE-2021-2145, CVE-2021-2309, CVE-2021-2310)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. CVSS 3.1 Base Score 8.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H). (CVE-2021-2250)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle VM VirtualBox accessible data as well as
    unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS
    3.1 Base Score 8.4 (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N). (CVE-2021-2264)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.0
    (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N). (CVE-2021-2266,
    CVE-2021-2306)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via RDP to compromise Oracle VM VirtualBox. Successful
    attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. CVSS 3.1 Base Score 8.1
    (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-2279)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows
    unauthenticated attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS
    3.1 Base Score 7.1 (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N).
    (CVE-2021-2280, CVE-2021-2282, CVE-2021-2283, CVE-2021-2285, CVE-2021-2287)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows
    unauthenticated attacker with logon to the infrastructure where Oracle VM VirtualBox executes to
    compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Oracle VM VirtualBox
    accessible data. CVSS 3.1 Base Score 7.1 (Integrity impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N). (CVE-2021-2281, CVE-2021-2284, CVE-2021-2286)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 4.7
    (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-2291)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Difficult to exploit vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 5.3
    (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N). (CVE-2021-2296,
    CVE-2021-2297)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.20. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. Note: This vulnerability
    applies to Windows systems only. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2312)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.24. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. CVSS 3.1 Base Score 8.2 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H). (CVE-2021-2409)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.24. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 6.0
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H). (CVE-2021-2442)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.24. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized
    update, insert or delete access to some of Oracle VM VirtualBox accessible data and unauthorized read
    access to a subset of Oracle VM VirtualBox accessible data. Note: This vulnerability applies to Solaris
    x86 and Linux systems only. CVSS 3.1 Base Score 7.3 (Confidentiality, Integrity and Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H). (CVE-2021-2443)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.24. Difficult to exploit vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. CVSS 3.1 Base Score 7.0 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-2454)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.28. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 4.4
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-2475,
    CVE-2021-35542)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.28. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. Note: This vulnerability does not apply to Windows systems. CVSS 3.1 Base Score 7.8
    (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-35538)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.28. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 5.5
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H). (CVE-2021-35540)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.28. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox and unauthorized read access
    to a subset of Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.7 (Confidentiality and
    Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H). (CVE-2021-35545)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.32. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 6.5
    (Confidentiality impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N). (CVE-2022-21394)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.34. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox as well as
    unauthorized update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.1
    Base Score 6.7 (Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:L/A:H). (CVE-2022-21465)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.34. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1
    Base Score 6.5 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H).
    (CVE-2022-21471)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.34. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 3.8 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N). (CVE-2022-21487)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.34. Easily exploitable vulnerability allows low
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle VM VirtualBox accessible data. CVSS 3.1 Base Score 3.8
    (Integrity impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N). (CVE-2022-21488)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.36. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 4.4
    (Availability impacts). CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H). (CVE-2022-21554)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.36. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in takeover of
    Oracle VM VirtualBox. CVSS 3.1 Base Score 8.2 (Confidentiality, Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H). (CVE-2022-21571)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-36");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=785445");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803134");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=820425");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831440");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=839990");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=859391");
  script_set_attribute(attribute:"solution", value:
"All VirtualBox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-emulation/virtualbox-6.1.36");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2279");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-additions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-extpack-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-guest-additions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:virtualbox-modules");
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
    'name' : "app-emulation/virtualbox",
    'unaffected' : make_list("ge 6.1.36", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.1.36")
  },
  {
    'name' : "app-emulation/virtualbox-additions",
    'unaffected' : make_list("ge 6.1.36", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.1.36")
  },
  {
    'name' : "app-emulation/virtualbox-extpack-oracle",
    'unaffected' : make_list("ge 6.1.36", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.1.36")
  },
  {
    'name' : "app-emulation/virtualbox-guest-additions",
    'unaffected' : make_list("ge 6.1.36", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.1.36")
  },
  {
    'name' : "app-emulation/virtualbox-modules",
    'unaffected' : make_list("ge 6.1.36", "lt 6.0.0"),
    'vulnerable' : make_list("lt 6.1.36")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle VirtualBox");
}
