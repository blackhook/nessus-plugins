##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K08832573.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(161405);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2021-25217");

  script_name(english:"F5 Networks BIG-IP : DHCP vulnerability (K08832573)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K08832573 advisory.

  - In ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16, ISC DHCP 4.4.0 -> 4.4.2 (Other branches of ISC DHCP (i.e., releases
    in the 4.0.x series or lower and releases in the 4.3.x series) are beyond their End-of-Life (EOL) and no
    longer supported by ISC. From inspection it is clear that the defect is also present in releases from
    those series, but they have not been officially tested for the vulnerability), The outcome of encountering
    the defect while reading a lease that will trigger it varies, according to: the component being affected
    (i.e., dhclient or dhcpd) whether the package was built as a 32-bit or 64-bit binary whether the compiler
    flag -fstack-protection-strong was used when compiling In dhclient, ISC has not successfully reproduced
    the error on a 64-bit system. However, on a 32-bit system it is possible to cause dhclient to crash when
    reading an improper lease, which could cause network connectivity problems for an affected system due to
    the absence of a running DHCP client process. In dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd
    server binary was built for a 32-bit architecture AND the -fstack-protection-strong flag was specified to
    the compiler, dhcpd may exit while parsing a lease file containing an objectionable lease, resulting in
    lack of service to clients. Additionally, the offending lease and the lease immediately following it in
    the lease database may be improperly deleted. if the dhcpd server binary was built for a 64-bit
    architecture OR if the -fstack-protection-strong compiler flag was NOT specified, the crash will not
    occur, but it is possible for the offending lease and the lease which immediately followed it to be
    improperly deleted. (CVE-2021-25217)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K08832573");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K08832573.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/20");

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

var sol = 'K08832573';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','15.1.9'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
