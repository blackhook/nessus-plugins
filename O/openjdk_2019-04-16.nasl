#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151214);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-2602", "CVE-2019-2684", "CVE-2019-2698");

  script_name(english:"OpenJDK 7 <= 7u211 / 8 <= 8u202 / 11.0.0 <= 11.0.2 / 12.0.0 <= 12.0.0 Multiple Vulnerabilities (2019-04-16)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u211 / 8 <= 8u202 / 11.0.0 <= 11.0.2 / 12.0.0 <=
12.0.0. It is, therefore, affected by multiple vulnerabilities as referenced in the 2019-04-16 advisory.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: 2D). Supported versions that are
    affected are Java SE: 7u211 and 8u202. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability
    can result in takeover of Java SE. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). CVSS 3.0 Base Score 8.1 (Confidentiality,
    Integrity and Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2019-2698)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 7u211, 8u202, 11.0.2 and 12; Java SE Embedded: 8u201.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Java SE, Java SE
    Embedded. Note: This vulnerability can only be exploited by supplying data to APIs in the specified
    Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a
    web service. CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2602)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: RMI). Supported
    versions that are affected are Java SE: 7u211, 8u202, 11.0.2 and 12; Java SE Embedded: 8u201. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Java SE, Java SE Embedded accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. CVSS 3.0 Base Score 5.9 (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N). (CVE-2019-2684)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2019-04-16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u211 / 8u202 / 11.0.2 / 12.0.0");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2698");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
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

var app_list = [
        'OpenJDK Java',
        'AdoptOpenJDK'
];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.211', 'fixed_display' : 'Upgrade to a version greater than 7u211' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.202', 'fixed_display' : 'Upgrade to a version greater than 8u202' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.2', 'fixed_display' : 'Upgrade to a version greater than 11.0.2' },
  { 'min_version' : '12.0.0', 'max_version' : '12.0.0', 'fixed_display' : 'Upgrade to a version greater than 12.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
