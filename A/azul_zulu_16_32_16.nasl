#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153989);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-2341",
    "CVE-2021-2369",
    "CVE-2021-2388",
    "CVE-2021-2432"
  );
  script_xref(name:"IAVA", value:"2021-A-0327-S");

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2021-07-20)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is prior to 6 < 6.41.0.12 / 7 < 7.47.0.14 / 8 < 8.55.0.14 / 11 <
11.49.14 / 13 < 13.41.12 / 15 < 15.33.12 / 16 < 16.32.16. It is, therefore, affected by multiple vulnerabilities as
referenced in the 2021-07-20 advisory.

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Networking). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle
    GraalVM Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise
    Edition. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.1 (Confidentiality
    impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2021-2341)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Library). Supported versions that are affected are Java SE: 7u301, 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Oracle
    GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.3 (Integrity impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N). (CVE-2021-2369)

  - Vulnerability in the Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component:
    Hotspot). Supported versions that are affected are Java SE: 8u291, 11.0.11, 16.0.1; Oracle GraalVM
    Enterprise Edition: 20.3.2 and 21.1.0. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in takeover of Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.1 Base Score 7.5 (Confidentiality, Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H). (CVE-2021-2388)

  - Vulnerability in the Java SE product of Oracle Java SE (component: JNDI). The supported version that is
    affected is Java SE: 7u301. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs. CVSS 3.1
    Base Score 3.7 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2021-2432)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/zulu-openjdk/release-notes/july-2021");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2021 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

if ('NV' == package_type)
{
  audit(AUDIT_PACKAGE_NOT_AFFECTED, package_type);
}
else if ('SA' == package_type)
{
  var constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.41.0.12', 'fixed_display' : 'Upgrade to a version 6.41.0.12 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.47.0.14', 'fixed_display' : 'Upgrade to a version 7.47.0.14 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.55.0.14', 'fixed_display' : 'Upgrade to a version 8.55.0.14 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.49.14', 'fixed_display' : 'Upgrade to a version 11.49.14 (SA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.41.12', 'fixed_display' : 'Upgrade to a version 13.41.12 (SA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.33.12', 'fixed_display' : 'Upgrade to a version 15.33.12 (SA) and above' },
    { 'min_version' : '16.0.0', 'fixed_version' : '16.32.16', 'fixed_display' : 'Upgrade to a version 16.32.16 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  var constraints = [
    { 'min_version' : '7.0.0', 'fixed_version' : '7.48.0.11', 'fixed_display' : 'Upgrade to a version 7.48.0.11 (CA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.56.0.21', 'fixed_display' : 'Upgrade to a version 8.56.0.21 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.50.19', 'fixed_display' : 'Upgrade to a version 11.50.19 (CA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.42.17', 'fixed_display' : 'Upgrade to a version 13.42.17 (CA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.34.17', 'fixed_display' : 'Upgrade to a version 15.34.17 (CA) and above' },
    { 'min_version' : '16.0.0', 'fixed_version' : '16.32.15', 'fixed_display' : 'Upgrade to a version 16.32.15 (CA) and above' }
  ];
}
else
{
  audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Azul Zulu Java ' + package_type);
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
