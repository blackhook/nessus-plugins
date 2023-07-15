#TRUSTED 140520d6bd70908635bd24a683d992c8b8b0ac8b7b0dfc464b3cac994f4039fbbf334be15d8aa2476deeb5eb724c4cae51c6bc816d620890b8c0928c6e7de6231d9009f3042db7837ca9dc4f42207ee9315e995f864a5555ad83216b41f7754d1a74a7af5928c71bd7a23708205aed7b9a39d14b3d6233b34df47976ae19ca1555f0b1ace94b2846b6a39b9c37ed1e2eb9169420cc8a933d525137132c947fe2c10c49f86ab8daf3d639b6d8ab02a1050c6bc021aeaa1374e247df13223be67b6cfbbe1435481a68530caa26076e06f49a378ba1073caf3d8bd31e1d0101cea30464b0e59e0ea3ae26b5d0cf9a9cc6b074d3e77bbb4b79e55894feb5c99cf62ae92fecbb7ebf26cba3276881eed00917fed4c027af7b0b2f22b9f79fe84ebb1f31d03c6b5d81aaf05c9ec4912162b541c2e417154e040efcdba4c2fe87e57f01ee42a4f912ef6a88ec20c543905f697440bba061fca8816b837aa2f90e840d68b4a063e7f61e465a40773dbea6a4b7eecb83cb9e394f3bb1dfce1a0ef76aa08ae0eaa691f613fae9ec6ee4b8b41a5665c56066ca2c0bc971d59791961c8224dab12ea7723b85f4caaf78be4f1d4bf94dfb6a4ff9c4fa7623a9a070e9c61a5986fdb4789b98c98fd31c1b68b12fa5e48d8bdb14c1031fe1ff6b54c7c4f3dae5309066309b95e77b531fc0832a2a85b56a074b6433bfb9be2dab7d5827d2a79dcd
#TRUST-RSA-SHA256 37b57f1769757e3ecb1dfeff188d77e374e5dec38d6405f8bbf0bf549d81ee7e6b1a7aac930f41105f79ea01302c40f54434b93400269bd0760bb3b26088d258daf2d1927cc7b95fb1f0803638d8a84180ff0d1f436f579313b992b3c34f4a41ff954b665c06c1807b569b10b430bfcf0ad59369dcc91def38ff8dd3eae6c3a2015c26dc434fc34de158dd9ccebc8a51fe6540ff9273f5664bf87a19d67dc2cc690282de25137e98fcc9515c46bc7723b80bf8dc217c81cba897d21a5237dc2368c7e0bedc8a9dc870ed63bf1a3ca8afe1e67a460a020b3ccfd21c882b345d0d30441bb2d77f79167ccaedd8bce1eeb35959eb5ff75e7b0a283512d441cb34719d646a914ba2f0f2d8d58c059fb69eddb65a1f61c77d06d8ff8fb8d5b5ee2c4e4cd013505fc18ecb0c264489dd9fef14246a1ab51b26b24bce483a92d42ea0fd668ee318bb31d3abcb2f6ddd235ebfcefe0015df45d55b9f92284b5042b6e89e6205a9ac4247f5648888e49941b283f4043d0074b9b66962aa02275e540c88a8aec31bfb5bd859ce5faa5074357e840cef32400c58ddd317f451d708290db17cc874e77935f18f5a086eeb9d01ac5449ba90b3de77a8261f788586b7a8be84eeb9074c02bb9525a649a6793328dd71bbd3f56d10ecfe0e81bcc0cd9bf21b21a3a05333c34562e2c72b1af59b9bc5865596a9cc013358b7fe6adb3f9600d54c08
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165761);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2022-20814");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa25108");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-csrf-sqpsSfY6");
  script_xref(name:"IAVA", value:"2022-A-0399-S");

  script_name(english:"Cisco Expressway Series and Cisco TelePresence VCS Improper Certificate Validation Vulnerability (cisco-sa-expressway-csrf-sqpsSfY6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Expressway-C and Cisco TelePresence VCS devices are 
affected by a vulnerability in the certificate validation that could allow an unauthenticated, remote attacker to gain
unauthorized access to sensitive data. The vulnerability is due to a lack of validation of the SSL server certificate 
that an affected device receives when it establishes a connection to a Cisco Unified Communications Manager device. 
An attacker could exploit this vulnerability by using a man-in-the-middle technique to intercept the traffic between 
the devices, and then using a self-signed certificate to impersonate the endpoint. A successful exploit could allow the
attacker to view the intercepted traffic in clear text or alter the contents of the traffic.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-csrf-sqpsSfY6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b189acd2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa25108");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa25097, CSCwa25108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');
var vuln_ranges = [{ 'min_ver':'14.0', 'fix_ver' : '14.2' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwa25108',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);