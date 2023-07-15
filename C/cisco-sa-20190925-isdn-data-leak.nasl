#TRUSTED 10c85cda387b736e65d5d3d99821da8f84686fc36300be4b438fb4e69398924f5add8dc35bdf899526a66068e95ecdc1c8fc070f04966990f58eb11c0439287f05afd8bf6ee93cd670fcbe92f1d7d18e5b78f3e54bf487eae197f0fad95d84febc577cd7f419c19b4ce365d446014d1b8cdf0767272d97997bbe024bf4bfc2be579d60d2133d3940cda8d47544b11f47d124dd886cbf33a93ec59cb5973c971fc8013003d6d852da783fd20e4992fa5d4e90531295ca4de453be926e05ff1282529fdbe24fffc8a1a5170cd9437366745f76a2a1459d667c1cff87844abcc741276f9a510425edd2277436bff65fed57c55ec94766216a6ba341910705ea0874b9e64dd6f6ffb3e5f3fe5223926638a2490e48a08a1c7cd5aa5ce9a13581859c6fa18aee16a2e55c0da23c8a517aeb2c362f1bc73288e4ee0027d723da0d6c0b0de39dee736bfff4f74bd04ed28824558d6bb0780bff021432ff1bd33530b7c88eee5db964198f116dd95f91d167d1f3249b91fe71deb03c33ce74a242bb0ec7308b664d77aeb7177c57981c9268505be9df8a6fbbbaa36b71698fb765e5584d8bd0bc37e62f761368d2f0c766ca434cdf84ca82bbdf5d01ff106df892129e5f3159cb16d7c89a899cfad0755d2211495f16bfc30a4f41a1662d48e230eecbd7c06dd3f7a5392b4015096f14dc798b7181a8a48110740c58aa7ce0d4b42933d9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129530);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12664");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk42668");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-isdn-data-leak");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software ISDN Data Leak Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a data leak vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-isdn-data-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32058d0a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk42668");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk42668");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.6.5bE',
  '3.4.6SG',
  '3.4.5SG',
  '3.2.9SG',
  '3.2.11aSG',
  '3.2.0JA',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.14.0S',
  '3.13.9S',
  '3.13.1S',
  '16.9.3h',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk42668'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
