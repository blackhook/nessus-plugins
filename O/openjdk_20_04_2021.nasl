#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151207);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-2161", "CVE-2021-2163");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"OpenJDK 7 <= 7u291 / 8 <= 8u282 / 11.0.0 <= 11.0.10 / 13.0.0 <= 13.0.6 / 15.0.0 <= 15.0.2 / 16.0.0 Multiple Vulnerabilities (2021-04-20)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u291 / 8 <= 8u282 / 11.0.0 <= 11.0.10 / 13.0.0 
<= 13.0.6 / 15.0.0 <= 15.0.2 / 16.0.0. It is, therefore, affected by multiple vulnerabilities as referenced in the
2021-04-20 advisory. 

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. It can also be exploited by supplying untrusted data to APIs in the
    specified Component. 

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. 

Please Note: 
  - Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using
the patch versions from the referenced OpenJDK security advisory.
  - Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2021-04-20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u291 / 8u282 / 11.0.10 / 13.0.6 / 15.0.2 / 16.0.0");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adoptopenjdk_nix_installed.nbin", "adoptopenjdk_win_installed.nbin", "openjdk_win_installed.nbin", "openjdk_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['OpenJDK Java', 'AdoptOpenJDK'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.291', 'fixed_display' : 'Upgrade to a version greater than 7u291' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.282', 'fixed_display' : 'Upgrade to a version greater than 8u282' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.10', 'fixed_display' : 'Upgrade to a version greater than 11.0.10' },
  { 'min_version' : '13.0.0', 'max_version' : '13.0.6', 'fixed_display' : 'Upgrade to a version greater than 13.0.6' },
  { 'min_version' : '15.0.0', 'max_version' : '15.0.2', 'fixed_display' : 'Upgrade to a version greater than 15.0.2' },
  { 'min_version' : '16.0.0', 'max_version' : '16.0.0','fixed_display' : 'Upgrade to a version greater than 16.0.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
