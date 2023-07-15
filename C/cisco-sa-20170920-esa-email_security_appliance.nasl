#TRUSTED 9feae1097dba0466d90ee1606a770ed15d85c3f7088a0f64ab8a69a6fa92a447aec4f3c2275921e21697c23701b7641f357d1b7851a6aa2bf0ac59111e7a333195ac7dd419fd5700151d2e311ec6dd641084466aa2508c3cbad844a95ef9f7f094f6c01d0ff41226531414933cbb97030cd2391a04b07fadc35c4014fb5cc3b68b8093601fc2773812764230d3b61ba6e542b7c5dfcf32fd03a85cb0c4e687e1c39519d9b1808da5857e95771b61205d748ff6d4c72379ef121a7dc46d644efd591e83fc71d1dbc7a46e2f8feb4ca2b0a013bfe9d395611b69d400c5462cb224253077930ec330001d7d71c980d264a0857fdb6c4678706a6b200c89b2c79af00671905b1f5a608548a12a56b4fac21a45956fb73c211ead273fa595d34bd71352933a8235b233314d9565bc73d6c99bdea5259b401cf66eec56ea654174051f90e8598e086f7e060c5ebe9dad3414ff5bf8fbfbcff9b15c77105eae72500309a2fe5c52adbd7048e38e77972835c1b2fcb3bda041b418fd35a7774c9b05dca99093e0d4c8a2dfa777839efe1d98cfd3cdd92199136b8fbcf7da5519893f11ed0226fece270187e649f935819471380be180b9a263327b749457e6e7a45321effda107e5467bd11562d6c69bc5b567459e3b9484849459b4b2c59a4179672f22c213e682f35cb540352cd84c8ba818742356259ddb703d6d8e2fb4ca2585921b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103459);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2017-12215");
  script_bugtraq_id(100920);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd29354");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170920-esa");

  script_name(english:"Cisco Email Security Appliance Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Email Security Appliance (ESA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security Appliance (ESA) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170920-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0810e81f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd29354");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd29354.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

# Since we can not reliably check the configuration for filters
# we are simply doing a version check and running on paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

version_list = make_list(
  "9.7.1.066",
  "9.7.2.065",
  "10.0.0.203",
  "10.0.1.087"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCvd29354"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
