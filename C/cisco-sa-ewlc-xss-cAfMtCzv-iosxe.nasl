#TRUSTED 622c53029bf5ae8d9b26980f70f913bf13c418bdc0382bda74d10191fb0d954add5f0c468edd6a23f40e59e061cd84069515bc8ef5819a95cab1677b7319b51fe6c40f23e8ac66a3d2499480a2b2576b644a78e6e6431c1ba0c38185ff51a571a3cd2a0fb2ec9ba9fa0081e94df063bf608527e9ca831e8919de5b9bdc991f8135b49a5528a38f5f9790a09ce2aa90ad182d3e1f6ebf218ae303e95b05ba26dd364f04b470940a1349ece0aead55eddb6d4874260a78b98fd2dc36b5b29263b499a9afb358e12a25452da3732040babecfac0c94ff71b914864216670a4a1ff2178b82421df9e354943a4dec63f6c75890462b6460b97edf83ebb0fdee359ff7f5c918a18b87eae9d399477ecfd9b56ea040473ac2282ebb2e1240921a378e8764b1e90b0bc86a5e4b8f3e98ffc0b456002cd7bf0be23ca2d7e98b252e3870bb023a8ec09a538e9b7e4728afaf9e7f6c5d9893fe478087f1b887eaa15dce45254fe75e0ea5e084c59fa8882b3ea20204af63410f452254f1b20e4bdff3052ff60271cf6624a5365013640e609f8ee6240e333dd25c2f2ac88476a5a428e4ca9f04ad233f0169196ca46f325f67b80747543ef687c461a4152bf288d9d373cd0f8910b553325ae83eb9b2445a661c6db6ea2b9186cf0a56e6d3785f324eaa37fbd7f0034b9ae780e9d6b3e45e421ac2ca4bf3fe401cac9e65bbf9f66f4963225a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148092);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2021-1374");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv02020");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-xss-cAfMtCzv");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family Stored Cross Site Scripting (cisco-sa-ewlc-xss-cAfMtCzv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-xss-cAfMtCzv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?904a8176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv02020");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv02020");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500')) &&
    (model !~ 'cat' || (model !~ '9800')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvv02020',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
