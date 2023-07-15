#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000132726.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(175822);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id("CVE-2023-28406");
  script_xref(name:"IAVA", value:"2023-A-0237");

  script_name(english:"F5 Networks BIG-IP : Configuration utility Directory Traversal (K000132768)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 17.1.0 / 16.1.3.4 / 15.1.8.2 / 14.1.5.4. 
It is, therefore, affected by a vulnerability as referenced in the K000132768 advisory. A directory traversal 
vulnerability exists in an undisclosed page of the BIG-IP Configuration utility that may allow an authenticated 
attacker to read files with an .xml extension. Access to restricted information is limited and the attacker 
does not control what information is obtained. (CVE-2023-28406)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K000132768");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000132768.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000132768';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'AM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'AVR': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'LC': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
    ],
  },
  'WAM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.3.4','15.1.8.2','14.1.5.4'
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
