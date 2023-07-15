##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K09121542.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(146409);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2021-22981");
  script_xref(name:"IAVA", value:"2021-A-0127");

  script_name(english:"F5 Networks BIG-IP : BIG-IP SSL/TLS vulnerability (K09121542)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 13.0.0. It is, therefore, affected by a
vulnerability as referenced in the K09121542 advisory.

  - On all versions of BIG-IP 12.1.x and 11.6.x, the original TLS protocol includes a weakness in the master
    secret negotiation that is mitigated by the Extended Master Secret (EMS) extension defined in RFC 7627.
    TLS connections that do not use EMS are vulnerable to man-in-the-middle attacks during renegotiation.
    Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.
    (CVE-2021-22981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K09121542");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K09121542.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K09121542';
var vmatrix = {
  'AFM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'AM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'APM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'ASM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'AVR': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'GTM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'LC': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'LTM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
    ],
  },
  'PEM': {
    'affected': [
      '12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '13.0.0'
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
