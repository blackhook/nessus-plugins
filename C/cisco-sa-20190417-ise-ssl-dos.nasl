#TRUSTED 760db5b1f4dd53ec2b2977549b61e7fcf0fd5cf78cd2d340e752099b49ecddf5f8bc826afea6a6331d3bb14d1843ab79b136dc18068392310a4a4bbc1757b43ef1f8eb366524fa3736febb64ebd7a90e707b42b266db49d41a3861addcdf4534a06534bd678458d6264ef433ca0831400db93e570e8ac5007c0db3d034282bd0762dbc006dbcbba185bf7135043dac183aff7636c229ec045f133bd7eb978f6f4e1eaeed85849992f6838fb5b61d486219d5e1d14aa7834a1812f68f4cb0edc75ecba64298e7f383411aa80a64a8ba5c105cc7501478baa3f3ee2f1f1192f33bcc5db6e7a5378336e32b99dd59aa7c1301f40849c0a75745b0620f19d5822a423596d6d96b11cb32ca6cfeb3e47aefa522cd830761861a04cca54891d38a993e95370ac2972e65ef05af7569cbe1136c8de922e6ff7ce8151db18ef8ebd8781483cb34f31727a7dba2690407c98bcc5a1d54256ecb138e36488b15aff156fd3b02b1581550a7b4d6ea7b907d74b8b599a4c99fc70170c88b71cf37a05ed754261b7899ea7adfafbab98b7f9a09b3b27b5f51be758689bdd61387253504d28184892a0776d5dffde76c1a6bb5f1e6ea8dba342f12609e41602464cab13c3ff0e18c5b73782351ef666deff2dbe04cba423c39d923f35bb383d0a9dcff37c37216878c7abbb3560a625683de0f15cf9c55f7f257b2f8ddb36224c2e3c5615d3be8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126101);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2019-1718");
  script_bugtraq_id(108030);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo10487");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ise-ssl-dos");

  script_name(english:"Cisco Identity Services Engine SSL Renegotiation Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco Identity Services Engine Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a vulnerability in the
web interface of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to trigger high
CPU usage, resulting in a denial of service (DoS) condition. The vulnerability is due to improper handling of Secure
Sockets Layer (SSL) renegotiation requests. An attacker could exploit this vulnerability by sending renegotiation
requests at a high rate. An successful exploit could increase the resource usage on the system, eventually leading to a
DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-ise-ssl-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2b53142");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo10487");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo10487");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
  { 'min_ver' : '2.1.0', fix_ver : '2.2.0.470' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if 
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.2\.0($|[^0-9])") required_patch = '14';

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo10487',
  'fix'      , '2.2.0.470 Patch 14'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges, required_patch:required_patch);
