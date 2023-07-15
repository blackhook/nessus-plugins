#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170112);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2023-21830", "CVE-2023-21835", "CVE-2023-21843");

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2023-01-17)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is prior to 6 < 6.53.0.12 / 7 < 7.59.0.18 / 8 < 8.67.0.22 / 11 <
11.61.18 / 13 < 13.53.18 / 15 < 15.45.18 / 17 < 17.39.20 / 19 < 19.32.14. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2023-01-17 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Serialization). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf;
    Oracle GraalVM Enterprise Edition: 20.3.8 and 21.3.4. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2023-21830)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JSSE). Supported versions that are affected are Oracle Java SE: 11.0.17, 17.0.5, 19.0.1;
    Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via DTLS to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2023-21835)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Sound). Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf, 11.0.17,
    17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and 22.3.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2023-21843)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/zulu-openjdk/release-notes/january-2023");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2023 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

if ('SA' == package_type)
{
var constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.53.0.12', 'fixed_display' : 'Upgrade to a version 6.53.0.12 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.59.0.18', 'fixed_display' : 'Upgrade to a version 7.59.0.18 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.67.0.22', 'fixed_display' : 'Upgrade to a version 8.67.0.22 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.61.18', 'fixed_display' : 'Upgrade to a version 11.61.18 (SA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.53.18', 'fixed_display' : 'Upgrade to a version 13.53.18 (SA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.45.18', 'fixed_display' : 'Upgrade to a version 15.45.18 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.39.20', 'fixed_display' : 'Upgrade to a version 17.39.20 (SA) and above' },
    { 'min_version' : '19.0.0', 'fixed_version' : '19.32.14', 'fixed_display' : 'Upgrade to a version 19.32.14 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  var constraints = [
    { 'min_version' : '8.0.0', 'fixed_version' : '8.68.0.19', 'fixed_display' : 'Upgrade to a version 8.68.0.19 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.62.17', 'fixed_display' : 'Upgrade to a version 11.62.17 (CA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.54.17', 'fixed_display' : 'Upgrade to a version 13.54.17 (CA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.46.17', 'fixed_display' : 'Upgrade to a version 15.46.17 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.40.19', 'fixed_display' : 'Upgrade to a version 17.40.19 (CA) and above' },
    { 'min_version' : '19.0.0', 'fixed_version' : '19.32.13', 'fixed_display' : 'Upgrade to a version 19.32.13 (CA) and above' }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
