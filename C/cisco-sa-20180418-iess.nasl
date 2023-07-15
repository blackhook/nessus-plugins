#TRUSTED a022dfb71ba3fcc477c4b445ccd7d7c144d0f6508714adbc3d140e376351d96c0755b4fd8ba0f20cb9dc7ef7c556e76909c6717e8ad638fe4ef09296dc4ce7a237fd943b36bb0f3cf948f99f4bb7990fa27a68c759362ae87e0a89de71af63f3147a8c4e79733b754d3ea12b7d8585304eb8ef12f4aa0530ea6cb2b16f77da533b5cddc508a462f3aaa5703075295d04cdb4ee0c706bfb6cd89efcfe3117b121357d8301bed011fe866fc80a1d6e5af5d5286791a323297d147f6700134d20e7f67fd322f41bf37b028b043025c4c2192e5cdb5c1d6589ce90885f3a7fb4280e3afd4274c355a051770d32162e07e7055f4dbeb09eaf58b6ad9bb36a6858e1b0082f338217e4fa10fcffb25788dca835656fd8b0a2fe046dfed7bd1f4d7adee2a0c66601e1165d01f70ce4bea0eaeda46bce84006d223f7b44594872f4787107a68c1f9043d127e46dc39cdadbefcc347d259f7855caf55401ac5b615e6e08a703b4d6f32c60f7a0acd969f62b065e869b855a67048dee84d2cc9d9087a5dad0881917214a4ced82d44377119ef66d71dce5d44518de658054c9dacbcef0beb7082ad0a40562e6a2049adfd37138de0a3e455e089ec2bd6c4ea1301ed8410db8f11618df86ec9cb36a4c6c9b78a6f5e5a505cf7bf5af594bccd91c611c265adc02c9fb4af6b3572c12a331c9300758ad8c3de7cdcf0580a80d7516671d64800f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132042);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-0255");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc96405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-iess");

  script_name(english:"Cisco Industrial Ethernet Switches Device Manager CSRF (cisco-sa-20180418-iess)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS on Cisco Industrial Ethernet (IE) Switches is affected by a
cross-site request forgery (CSRF) vulnerability due to insufficient CSRF protection by the device manager web
interface. An unauthenticated, remote attacker can exploit this, by persuading a user of the interface to follow a
malicious link or visit an attacker-controlled website, in order to submit arbitrary requests to an affected device via
the device manager web interface with the privileges of the user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-iess
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46ece8db");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc96405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvc96405.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');

model = product_info.model;

if (model !~ "IE-2000(U?)-" && model !~ "IE-[34]0[01]0-" && model !~ "IE-5000-")
 audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '15.2(6)E1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvc96405'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  switch_only:TRUE
);
