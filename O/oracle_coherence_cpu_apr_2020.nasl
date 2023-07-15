#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137853);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-2915", "CVE-2020-2949");

  script_name(english:"Oracle Coherence (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities, as referenced in the April 2020 Oracle CPU advisory.

- Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching, CacheStore, Invocation). 
Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability 
allows unauthenticated attacker with network access via IIOP, T3 to compromise Oracle Coherence. Successful attacks of this 
vulnerability can result in takeover of Oracle Coherence. 

- Vulnerability in the Oracle Coherence product of Oracle Fusion Middleware (component: Caching, CacheStore, Invocation). 
Supported versions that are affected are 3.7.1.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0. 
Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Coherence. 
Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle Coherence accessible data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:coherence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_coherence_installed.nbin");
  script_require_keys("installed_sw/Oracle Coherence");

  exit(0);
}

include('vcf.inc');

app_name = 'Oracle Coherence';

app_info = vcf::get_app_info(app:app_name);
 
constraints = [
  { 'min_version' : '3.7.1.0', 'fixed_version' : '3.7.1.18' },
  { 'min_version' : '12.1.3.0.0', 'fixed_version' : '12.1.3.0.8' },
  { 'min_version' : '12.2.1.3.0', 'fixed_version' : '12.2.1.3.7' },
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.4' }
];
 
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
