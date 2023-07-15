#TRUSTED 52b2923a69acc1c3faced3cd7160685dc97b29d0e3d979b3d09c320a1f205e9ce16a1f88313e10398db31b55dd34b7d42f2283ea70374f79f346f26db58c271f3d33c9bf665c69a5dd85f99d83d0464f9d86095f7c746e5a6899898106dca46a53c0d202e4d546eae3abe560330ec1b24600a89eb250b80ceb31ca56ad626e4a377b75862b608234ca5d1a123bb51b0f4f099912b00c3ad7b82e4c59f2a0b3762ad712325d88b5e6a5039417eb7c298f989fb1104b5fa4f855721c2b7afd8b50e9cf207225f1ff5b20616808efca4f72f858bca71a5ad811c979c3daaa992b3f423f537285816f8028d1247af145214b3fde985bc861aca129cda336f3cb388bf012e5ac51f3b593ce55b117b08f40def82af00729501685b1b0c4f89b5d64263041707d269864bd364c19fd290f6edba03adf9f612f61cb621b7dcbd443d886e8f05b2da86256e3c3fe488e3a671218ad5952d8c3a70eab4637ee5394f3006e108694506c5e1d9b731fcf11ea95352a56d5fa29d193f9446fdb01066097f0d1f851ce5e257c07e770b73004f45f10a7208d8bfb86c5ad3940e2eaf0c52e77b47c713de90f267f13ce61e74b99afae2cf8552b6abde82d872829dde8c5cc0bd99baa795685872bafb1131463113866450562a9d64c38a0c0d617e78c797d2471ac0b5fb5bb13306c20d1d968b50e83016790c2b1e9da3fc351172408d4b3296a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134326);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2020-3165");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq72707");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-nxos-bgpmd5");
  script_xref(name:"IAVA", value:"2020-A-0087");

  script_name(english:"Cisco NX-OS Software Border Gateway Protocol MD5 Authentication Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is vulnerable to authentication bypass due to missing patch. (cisco-sa-20200226-nxos-bgpmd5)");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Cisco NX-OS Software Border Gateway 
Protocol due to MD5 Authentication Bypass. An unauthenticated, remote attacker can 
exploit this, via by attempting to establish a BGP session with the NX-OS peer, to bypass
authentication and execute arbitrary actions with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-nxos-bgpmd5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3876f25");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq72707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq72707");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ '^((90[0-9][0-9])|(30[0-9][0-9]))')
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '9.3(1z)',
  '9.3(1)',
  '9.2(3y)',
  '9.2(3)',
  '9.2(2v)',
  '9.2(2t)',
  '9.2(2)',
  '9.2(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['show_ip_vrf_md5'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq72707'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
