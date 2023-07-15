#TRUSTED 24c3aefe3983d765aae4ef54fa4f5ea533cf67fd7cfd43236b972e591cacea38667626186d7f7bb8239c942e55a8488b4ca9a395eaae2976e57f20d73b63ded4ae8837c1a3f917adf5d0fc4a7102c46c801cf22e880f1ab77bb407ed922bda20384cb61142b91df6a1fc8d20406d6e1da5ad2c977396907ca21b05ff249cb81d432fbebf424ac2775c26e163729ef99c7483db869330b24b08746ca171c9a15655c8e2fe844363db2e4c0cf74a6220d9b89508d16be4f917044ac3814c518622cfcf7b162d30bed12d3d8fe1d859441a7ef0bf299b18bb37a92cf0eab1cfc6d7d2f6bbd81bb0fd9c50e14e7817c2b6097e1c4e9aa26003544936a254502415265f14cd15f6c85caa14c35edcccff44db3cf7306ab67ffb9d6f4d7ce903dad4306172f71a5303465b03c7ad747bd28e440a8b7a0a3ceb53a7829d3b254b8030504ed6d41a8c40642d288206ddb1daef7b550a196841a2b8269d2dd2c3435d1ef8b5c35ab4f56517899f2a6ec706aa53ae5d84f54480aabe5c5538bad23ec90464833c4d7435c8114bafc262e3a59082adaea60976e70e4b4dff0c16fd894b0c7a65bee38022d92bfe37c33e77d00a6e1c98c91a3e81d164e4d56bc3bac9afa8977d5c7db2a6cc23386d316c91d7356b595a03574aa2e0bb36ad75802a6e1547a3f07787980bec0051ad5805aa4d150fa38e85bbe5e6eab90108b0c48f54678795
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124326);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2019-1711");
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve12615");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-ios-xr-dos");

  script_name(english:"Cisco IOS XR gRPC Software Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is
affected by following vulnerability :

  - A vulnerability in the Event Management Service daemon
    (emsd) of Cisco IOS XR Software could allow an
    unauthenticated, remote attacker to cause a denial of
    service (DoS) condition on an affected device.The
    vulnerability is due to improper handling of gRPC
    requests. An attacker could exploit this vulnerability
    by repeatedly sending unauthenticated gRPC requests to
    the affected device. A successful exploit could cause
    the emsd process to crash, resulting in a DoS condition.
    (CVE-2019-1711)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-ios-xr-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fe2d587");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve12615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCve12615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1711");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:'Cisco IOS XR');

vuln_ranges = [{'min_ver':'6.1', 'fix_ver':'6.5.1'}];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['grpc'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve12615'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
