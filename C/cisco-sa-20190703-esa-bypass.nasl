#TRUSTED 0f8ab8cf2d175a44125fffd052a009c2392e1c9d0b6cda3fd7a8c9ee35761e52a562fcf96156bbc120905f4d08a49fee7719a9eace00e85a44c81e7e08cb60a6f4de6a7d211c0d530b3fd75d35de8b2bb02a50565294c6c064743f16cb17ef7ce5f57879d4ba3ed0b8ba8f0736afa2ef4995abf59a8e3c19b4d8d4dccd247d0113880ab087e38ca2ed83bc1046bdf0b69a440d1d786dbe92bb042a42edc7d65710e05a1bcf94c58101d9028033bf409671220f81b60c87073e2222bf8afb10ef0c6880048d68b6a36d0bd403fe602c25febe3a5060cc04cc9b83a2686af4aae0a473362a2198cbfb5f0547f0f8a7bf21ecae5bae6d049042789b1d1c70b98f031387de52ab2f60746620a5eecd5c1f68d00d5bb572e84367d259d786af4083cafa11f370892b34c5a4ddd123293f30a0c2fb5ef48db5c16cfd19a778cb5b2b280a55b3ddbca587de860328bfdd76d48799bfff10da334d873a9d531cb66b56cb2461e7b16c9c560d46f4f62ab1a241825b8b3672206186dc8d7a29eadca9dcb608de602f16ae3daafad8718f822ec35b3ad4b7adecc13939d3fda28d0f7687d4029bf3313e0fad31e092da9f3ba01eb521230ab56c6a8ebfefa01733ea4ea4401fa8899f5e76ce7588c01fd12e3d979f9e6554a61b8d1d424352f500be27c8bb8a9b228d33ca26fe7fca52b2d4e9c742396dafc7e0ca3912aa622f5e8d44f9a2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128053);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1921");
  script_bugtraq_id(109044);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp88949");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-esa-bypass");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (cisco-sa-20190703-esa-bypass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by a vulnerability in the attachment
scanning of Cisco AsyncOS Software due to improper input validation
of the email body. An attacker can exploit this vulnerability by
naming a malicious attachment with a specific pattern. A successful
exploit allows the attacker to bypass configured content filters
that would normally block the attachment.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-esa-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0a41bc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp88949");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp88949.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1921");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

version_list = make_list(
  '12.0.0-419'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp88949'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
