#TRUSTED 3f0c717ed26dc4d98945b708d7f6d806a12ce9aeabfbc13759cfb243d5b4e541be06c3342e77aa79cf91b63b9dcac7a36ef00e24fb9258fd0ccf1fd4bdc6a6b44a4d6851663e5afd1711e7abe9778e24f17262f17be01d70760b87a4fdf11f6f5c94c0fdef4a3fe037edce9564e9206458bb1621e5f9eb2ad9f58a23842b3cafcd85a90155de247ba347f850539cfa5f1d96c92bc2ea74d285243078a0457886f260728e3350c2a22e12cf6158425ec6aa5d62860a1fe8ca75180341f25513248f8d3ff6a27c666d36341a1eeee04c180d88d352e362a7e65fec4c951a018f1d110eccab568f1da722929503a9417a130a59de254f66ec912382c5bfb22a2f4990701bcf2c354e0502ce1820536a80a4d4f832530a1ebd93dc3aedb7ce1c36a9241c60c2d84f1ccec0247ece7895fdfd527ccf7eedcd92cf6dd52d6087d6b51ab0c527a4423d2fe4010c9766b4d2ed569d2dea27d711eae320929cdc34245b7cfb2c1c02760f3226426ad8d7e17c570e161cd9bfdfb11507f98a3de30528b9d90a840dc03bd3db4c0a5ce4e2e6307e298d4f9d8319127dcedd4652928916a10e4561ae7e8c5d60edaa6f51486a39491c74d40b8fd9bf79a3a214b2471cc48b4287579ee101aab06904f3858eec96b3470175a3faaac8910aac293ea2516c4e9ea8620845937065bd77c1fd1a796fc041212d6900fbe936108308c3343f4e9fb6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134707);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2020-3193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs29764");
  script_xref(name:"CISCO-SA", value:"cisco-sa-prim-collab-disclo-FAnX4DKB");
  script_xref(name:"IAVA", value:"2020-A-0110-S");

  script_name(english:"Cisco Prime Collaboration Provisioning Information Disclosure (cisco-sa-prim-collab-disclo-FAnX4DKB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Collaboration Provisioning is affected by an information disclosure
vulnerability in the web-based management interface because replies from the web-based management interface include
unnecessary server information. An unauthenticated, remote attacker can exploit this, by inspecting replies received
from the web-based management interface, in order to obtain details about the operating system, including the web server
version that is running on the device, in order to perform further attacks.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-prim-collab-disclo-FAnX4DKB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be94c398");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs29764");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs29764");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3193");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include('vcf.inc');

app = 'Prime Collaboration Provisioning';
app_info = vcf::get_app_info(app:app, kb_ver:'Host/Cisco/PrimeCollaborationProvisioning/version');

# We got the version from the WebUI and its not granular enough
if (app_info['version'] == '12')
  audit(AUDIT_VER_NOT_GRANULAR, app, app_info['version']);

constraints = [
  { 'min_version' : '0.0', 'max_version' : '12.6.0.2742', 'fixed_display' : '12.6 SU2'}
]; 

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
