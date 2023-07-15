#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141801);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14798",
    "CVE-2020-14803"
  );
  script_xref(name:"IAVA", value:"2020-A-0477-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Java SE 1.7.0_281 / 1.8.0_271 / 1.11.0_9 / 1.15.0_1 Multiple Vulnerabilities (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business installed on the remote host is prior to 7 Update
281, 8 Update 271, 11 Update 9, or 15 Update 1. It is, therefore, affected by multiple vulnerabilities related to the
following components as referenced in the October 2020 CPU advisory:

  - Vulnerability in the Oracle GraalVM Enterprise Edition product of Oracle GraalVM (component: Java).
    Supported versions that are affected are 19.3.3 and 20.2.0. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle GraalVM
    Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized read access to a
    subset of Oracle GraalVM Enterprise Edition accessible data. (CVE-2020-14803)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Hotspot). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Java SE, Java SE Embedded accessible data as well as unauthorized read access to
    a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server deployment of
    Java. This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2020-14792)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JNDI). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14781)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Oracle Java'];

var app_info = vcf::java::get_app_info(app:app_list);

# 7u271, 8u261, 11.0.8 and 15.0.0
var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.281', 'fixed_display' : 'Upgrade to version 7.0.281 or greater' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.271', 'fixed_display' : 'Upgrade to version 8.0.271 or greater' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.0.9', 'fixed_display' : 'Upgrade to version 11.0.9 or greater' },
  { 'min_version' : '15.0.0', 'fixed_version' : '15.0.1', 'fixed_display' : 'Upgrade to version 15.0.1 or greater' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
