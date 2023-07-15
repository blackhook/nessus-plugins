#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170536);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id("CVE-2023-21830", "CVE-2023-21835", "CVE-2023-21843");

  script_name(english:"OpenJDK 7 <= 7u361 / 8 <= 8u352 / 11.0.0 <= 11.0.17 / 13.0.0 <= 13.0.13 / 15.0.0 <= 15.0.9 / 17.0.0 <= 17.0.5 / 19.0.0 <= 19.0.1 Multiple Vulnerabilities (2023-01-17");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u361 / 8 <= 8u352 / 11.0.0 <= 11.0.17 / 13.0.0 <=
13.0.13 / 15.0.0 <= 15.0.9 / 17.0.0 <= 17.0.5 / 19.0.0 <= 19.0.1. It is, therefore, affected by multiple vulnerabilities
as referenced in the 2023-01-17 advisory.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2023-01-17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u361 / 8u352 / 11.0.17 / 13.0.13 / 15.0.9 / 17.0.5 / 19.0.1");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adoptopenjdk_nix_installed.nbin", "adoptopenjdk_win_installed.nbin", "openjdk_win_installed.nbin", "openjdk_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = [
        'OpenJDK Java',
        'AdoptOpenJDK'
];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.361', 'fixed_display' : 'Upgrade to a version greater than 7u361' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.352', 'fixed_display' : 'Upgrade to a version greater than 8u352' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.17', 'fixed_display' : 'Upgrade to a version greater than 11.0.17' },
  { 'min_version' : '13.0.0', 'max_version' : '13.0.13', 'fixed_display' : 'Upgrade to a version greater than 13.0.13' },
  { 'min_version' : '15.0.0', 'max_version' : '15.0.9', 'fixed_display' : 'Upgrade to a version greater than 15.0.9' },
  { 'min_version' : '17.0.0', 'max_version' : '17.0.5', 'fixed_display' : 'Upgrade to a version greater than 17.0.5' },
  { 'min_version' : '19.0.0', 'max_version' : '19.0.1', 'fixed_display' : 'Upgrade to a version greater than 19.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
