##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163304);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2022-21540",
    "CVE-2022-21541",
    "CVE-2022-21549",
    "CVE-2022-25647",
    "CVE-2022-34169"
  );
  script_xref(name:"IAVA", value:"2022-A-0287-S");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is affected by multiple
vulnerabilities as referenced in the July 2022 CPU advisory:

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 
    Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1, 17.0.3.1, 18.0.1.1; 
    Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM 
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized read access to a subset of 
    Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. (CVE-2022-21540)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 
    Hotspot). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1, 17.0.3.1, 18.0.1.1; 
    Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Difficult to exploit vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM 
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or 
    modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. 
    (CVE-2022-21541)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 
    Libraries). Supported versions that are affected are Oracle Java SE: 17.0.3.1; Oracle GraalVM Enterprise Edition: 
    21.3.2 and 22.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this 
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM 
    Enterprise Edition accessible data. (CVE-2022-21549)

  - Vulnerability in the Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Native Image (Gson)). 
    Supported versions that are affected are Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle GraalVM 
    Enterprise Edition executes to compromise Oracle GraalVM Enterprise Edition. Successful attacks of this 
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of 
    Oracle GraalVM Enterprise Edition. (CVE-2022-25647)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JAXP 
    (Xalan-J)). Supported versions that are affected are Oracle Java SE: 7u343, 8u333, 11.0.15.1, 17.0.3.1, 18.0.1.1; 
    Oracle GraalVM Enterprise Edition: 20.3.6, 21.3.2 and 22.1.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM 
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation, deletion or 
    modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data.
    (CVE-2022-34169)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html#AppendixJAVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25647");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed.nasl", "sun_java_jre_installed_unix.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.351', 'fixed_display' : 'Upgrade to version 7.0.351 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.341', 'fixed_display' : 'Upgrade to version 8.0.341 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.16', 'fixed_display' : 'Upgrade to version 11.0.16 or greater' },
  { 'min_version' : '17.0.0', 'fixed_version' : '17.0.4', 'fixed_display' : 'Upgrade to version 17.0.4 or greater' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.0.2', 'fixed_display' : 'Upgrade to version 18.0.2 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
