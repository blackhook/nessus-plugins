#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K31323265.
#
# @NOAGENT@
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159139);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id("CVE-2022-0778");
  script_xref(name:"IAVA", value:"2022-A-0121-S");

  script_name(english:"F5 Networks BIG-IP : OpenSSL vulnerability (K31323265)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K31323265 advisory.

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K31323265");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K31323265.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var sol = 'K31323265';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'APM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'ASM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'DNS': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'GTM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'LTM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'PEM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'PSM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
    ],
  },
  'WOM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '17.0.0','16.1.2.2','15.1.5.1','14.1.4.6','13.1.5'
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
