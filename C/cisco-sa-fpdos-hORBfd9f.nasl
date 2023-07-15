#TRUSTED a18d69ae399c75a5b25e880a5978fd26fa33b4d304c8282593969c3606748858210286135772a3a99cc090165a18f1342c8c9cc87ba7e71657c3fcbb792799c1dae487ffc7d2985fc3c71577eaf3dcdb4d251af4a735bf347029de2fe9d4f5f1c7250d01ae29d62c9a708f252457fd27625e3fff0e3c640514e66641d8f0b0fdca85f55c5d96340c5d90cd3bba6d7d1e2b44337cae2a4134cac095b8a567f0a63ac05a8897149c08011973fe7c32f5c19fff5a9a9b7cdb107377afab20c94ee63cde40c04740073fa86b3b42f01cd08bee335630a5f29e19b2270bc7c002dc3d13b98a1e13796d242ee83dc951a0557ee8fe1f71e5c8a905eeec3ce5ad970e61775003d912517d8a041453a2cb8df081c20d565a53fd9e880b9da5d3ac0a3ae8227d5d9acdd7931fd17cec09c2e4ed14f3ef8fd5fa3894acafd88338775093ce47ecbc45c0650742c7841a9bdbcb51d734cb51f5c11c4fbe709645a2cd032bc6721454afc310ffd64af58f06d72731881643b92e95f1240285e6b0dda943fd28f38d780a604bc065494e6e3644c6c82c4740a405b03fd381ad56b8bbdf4d302b22a4a38d07a00d4dce22c0cb9bc193aa7410bb99ac7c42de081433e9e53623ef15ea33b6e46fb1ffd6c6197aa18878cdd9dbec33382d22382c1cadec6d6bb63436f0a957059a328f0d9ceea8ac2214d674665b9a15c321df1b1a67008edfe3ca
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147762);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3369");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs72669");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fpdos-hORBfd9f");

  script_name(english:"Cisco SD-WAN vEdge Routers DoS (cisco-sa-fpdos-hORBfd9f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vEdge routers are affected by a denial of service (DoS)
vulnerability in the deep packet inspection (DPI) engine due to improper processing of FTP traffic. An unauthentiated,
remote attacker can exploit this to cause a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fpdos-hORBfd9f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?063cc2e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs72669");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs72669.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:vedge_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vedge_cloud_router");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

# Not currently checking for DPI enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
    'vedge-cloud' >!< tolower(product_info['model']) &&
    ('vedge' >!< tolower(product_info['model']) || product_info['model'] !~  "vedge.*5(k|[0-9]{3})"))
  audit(AUDIT_HOST_NOT, 'an affected model');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs72669',
  'disable_caveat', TRUE,
  'fix'      , 'See vendor advisory'
);

version_list = make_list
(
  '19.2.0',
  '19.2.097',
  '19.2.098',
  '19.2.1'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
