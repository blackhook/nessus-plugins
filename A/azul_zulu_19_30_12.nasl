#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166222);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628",
    "CVE-2022-39399"
  );

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2022-10-18)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is prior to 6 < 6.51 / 7 < 7.57.0.14 / 8 < 8.65.0.14 / 11 <
11.59.16 / 13 < 13.51.14 / 15 < 15.43.14 / 17 < 17.37.14 / 19 < 19.30.12. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2022-10-18 advisory.

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JGSS). Supported versions that are affected are Oracle Java SE: 17.0.4.1, 19; Oracle GraalVM
    Enterprise Edition: 21.3.3 and 22.2.0. Easily exploitable vulnerability allows unauthenticated attacker
    with network access via Kerberos to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. This vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which supplies data to the APIs. (CVE-2022-21618)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM
    Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2022-21619)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: JNDI). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf, 11.0.16.1,
    17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition
    accessible data. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also
    be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to
    the APIs. (CVE-2022-21624)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Security). Supported versions that are affected are Oracle Java SE: 8u341, 8u345-perf,
    11.0.16.1; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTPS to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability can also be exploited by using
    APIs in the specified Component, e.g., through a web service which supplies data to the APIs.
    (CVE-2022-21626)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Lightweight HTTP Server). Supported versions that are affected are Oracle Java SE: 8u341,
    8u345-perf, 11.0.16.1, 17.0.4.1, 19; Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2022-21628)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE
    (component: Networking). Supported versions that are affected are Oracle Java SE: 11.0.16.1, 17.0.4.1, 19;
    Oracle GraalVM Enterprise Edition: 20.3.7, 21.3.3 and 22.2.0. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Java SE, Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2022-39399)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/zulu-openjdk/release-notes/october-2022");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'min_version' : '6.0.0', 'fixed_version' : '6.51', 'fixed_display' : 'Upgrade to a version 6.51 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.57.0.14', 'fixed_display' : 'Upgrade to a version 7.57.0.14 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.65.0.14', 'fixed_display' : 'Upgrade to a version 8.65.0.14 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.59.16', 'fixed_display' : 'Upgrade to a version 11.59.16 (SA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.51.14', 'fixed_display' : 'Upgrade to a version 13.51.14 (SA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.43.14', 'fixed_display' : 'Upgrade to a version 15.43.14 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.37.14', 'fixed_display' : 'Upgrade to a version 17.37.14 (SA) and above' },
    { 'min_version' : '19.0.0', 'fixed_version' : '19.30.12', 'fixed_display' : 'Upgrade to a version 19.30.12 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  var constraints = [
    { 'min_version' : '8.0.0', 'fixed_version' : '8.66.0.15', 'fixed_display' : 'Upgrade to a version 8.66.0.15 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.60.19', 'fixed_display' : 'Upgrade to a version 11.60.19 (CA) and above' },
    { 'min_version' : '13.0.0', 'fixed_version' : '13.52.15', 'fixed_display' : 'Upgrade to a version 13.52.15 (CA) and above' },
    { 'min_version' : '15.0.0', 'fixed_version' : '15.44.13', 'fixed_display' : 'Upgrade to a version 15.44.13 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.38.21', 'fixed_display' : 'Upgrade to a version 17.38.21 (CA) and above' },
    { 'min_version' : '19.0.0', 'fixed_version' : '19.30.11', 'fixed_display' : 'Upgrade to a version 19.30.11 (CA) and above' }
  ];
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
