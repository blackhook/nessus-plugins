##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K18484125.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(161332);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2020-27216");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"F5 Networks BIG-IP : Eclipse Jetty vulnerability (K18484125)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K18484125 advisory.

  - In Eclipse Jetty versions 1.0 thru 9.4.32.v20200930, 10.0.0.alpha1 thru 10.0.0.beta2, and 11.0.0.alpha1
    thru 11.0.0.beta2O, on Unix like systems, the system's temporary directory is shared between all users on
    that system. A collocated user can observe the process of creating a temporary sub directory in the shared
    temporary directory and race to complete the creation of the temporary subdirectory. If the attacker wins
    the race then they will have read and write permission to the subdirectory used to unpack web
    applications, including their WEB-INF/lib jar files and JSP files. If any code is ever executed out of
    this temporary directory, this can lead to a local privilege escalation vulnerability. (CVE-2020-27216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K18484125");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K18484125.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27216");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K18484125';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0','16.0.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5'
    ],
    'unaffected': [
      '15.1.9'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
}
else
{
  var tested = bigip_get_tested_modules();
  var audit_extra = 'For BIG-IP module(s) ' + tested + ',';
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, 'running any of the affected modules');
}
