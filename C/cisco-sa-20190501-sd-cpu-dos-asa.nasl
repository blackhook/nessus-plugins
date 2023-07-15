#TRUSTED 4560e6778a59417dc966d8020ddb3858937410947ccb581b730babb189bf055c2ccdac0a9e56de40d7c054d24412ce65cc634c38ab19bd0fced7df38efce0eacbee50b7a5b6d5227f8850f9de8f78059168d691f3f9ff3e122dd077a5cbd9a62b441f3230d880454428a270e7a7b00584c760707f3e9d75433302f18ea9ce5830decc0501fbee4c983233f2498db6d34074ee9185d7425e475f2dc65eaa47980f6d310edfb57f2d181b389d4a1a15d715db40f9eb435ea67c6f9f2ee7d8ac82e08a2c7344b2f0f8127bf05c0989ad28ed6cf1b63bc30214dfeaafa858470c7524eb87ca62f47988ad636a1baa1b643810d03ccd2864e86fe65609bfff61007470e0338a879797db3ed8b5312bd444c26e91d734730b584a1a9e0ee9494ca975f9f5f11e83c50e4322ce65e161b55b3aeeb3a3314ec0d7635c83e1ced878ef944ae5c465bece7a6011792f0dca9753c052a605dc737717b7296f0c32b192589cb6044787aba530b53e5a85ebc1e34e610c32010d45426731b5ca1dc25bace3ab7785622b995e75c11b668ee9959f1afb8ff2d37db33ea310744b550686e2f67a43212d71fcdd62a3ff73e54c08537f173947910010865021485b66146cd16690d5b956bb4fec7815b6ea055779b895e6b6d0cc250061d18663124d3352ee3341188ae4f8ebf68f26a2e5fb2896f7c8947666e6e41885e5105c35bc79ff6674e88
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136970);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2018-15388");
  script_bugtraq_id(108137);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj33780");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-sd-cpu-dos");

  script_name(english:"Cisco Adaptive Security Appliance (ASA) WebVPN DoS (cisco-sa-20190501-sd-cpu-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Adaptive Security Appliance (ASA) software installed on the remote
host is affected by a vulnerability in the WebVPN login process that allows an unauthenticated, remote attacker to cause
increased CPU utilization on an affected device. The vulnerability is due to excessive processing load for existing
WebVPN login operations. An attacker can exploit this vulnerability by sending multiple WebVPN login requests to the
device. A successful exploit could allow the attacker to increase CPU load on the device, resulting in a denial of
service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-sd-cpu-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7b5af9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj33780");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj33780");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

if (
  product_info.model !~ '^1000V' && # 1000V
  product_info.model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  product_info.model !~ '^5505($|[^0-9])' && # 5505
  product_info.model !~ '^55[0-9][0-9]-X' && # 5500-X
  product_info.model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  product_info.model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  product_info.model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  product_info.model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower 4100 SA
  product_info.model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  product_info.model != 'v' # ASA
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4(4.34)'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6(4.25)'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8(4)'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9(2.50)'}
];

workarounds = make_list(CISCO_WORKAROUNDS['ssl_vpn']);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj33780',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
