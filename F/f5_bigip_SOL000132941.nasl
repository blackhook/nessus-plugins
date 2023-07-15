#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000132941.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(177565);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2023-0286");

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (K000132941)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K000132941 advisory.

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000132941");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000132941.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var sol = 'K000132941';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
