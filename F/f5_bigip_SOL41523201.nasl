#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K41523201.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(149070);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/21");

  script_cve_id("CVE-2019-5482");

  script_name(english:"F5 Networks BIG-IP : cURL vulnerability (K41523201)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to
7.65.3. (CVE-2019-5482)

Impact

An attacker could cause a denial of service (DoS) or arbitrary code
executionif you use cURL to transfer data to or from a Trivial File
Transport Protocol (TFTP) serverand set the blksize (block size)
option to a value below 504 (the default value is 512). Setting a
smaller block size than the default should be rare as the primary use
case for changing the block size is to make it larger.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K41523201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K41523201.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5482");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K41523201';
var vmatrix = {
  'AM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.3','14.1.0-14.1.4','13.1.0-13.1.3','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.2','15.1.4','14.1.4.2','13.1.4.1'
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
