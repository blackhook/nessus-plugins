#TRUSTED 3d74bf0e0f54e70fe51ed4e0cf6218817ddfdccf4d3e7dcbd4b12b9e1e47b680ad5dc04a4e74ce783457c1c318b1fac396b2be4516098b015037a2913f167743398b686479aca0e606a930ce0fe17f2576400f6ac3fe1cf8895ccd3a7dd81d536d89d0a693f076cfc6308139f5c4ec85907be1e65351917c8d6ae165048f088876669d702921d55aa8b10ac283f43a87482a0b79a878e3d067b007934ed7e18efdf5d4546459b92afd3d734578db90c6aa91c4bbbd649031eb2dc0a48d54298b36542d14a9c3dea651432f45218a884a5345d400cbb69ab3e77d99b8019d2450b62185044a28bfb0baa1ba3281ced3ce3b77d09653c12a2cee5575b0af0978a32c25097c147ed96623fa1aac358f140db4c979af1e68e9043e08c5c217093c5720081e111d9043394be0fe13adc701f5c04ffdbd06b26bfe9741435d4a0899ea3defcfd4acb9d66a83bc499c679bccae75f0c5e213b2a2a2c63353ad9734e52a8e44f364ef48cc6090c204331c58a10386bbf171696a89c4975b855e0a145a0c109924e3c7e780086497dea8b63564f2839de630885a5677f758afd3c27ad2cc1a8d0cb46a89f27b2b8217ad6975f91ea97033c750deaa6d151745e87a1952a8e5dd6bfc09f845602e33cdfa26b3d18041102c04ae4fe44878552f7204d737eb5bae6c1e8ecf926bb7a99408614c31f5b5698ce11a442d2ecfc028a2a4b2d85f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126822);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-1831");
  script_bugtraq_id(108021);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo01349");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo78686");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-esa-filter-bypass");
  script_xref(name:"IAVA", value:"2019-A-0243-S");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (cisco-sa-20190417-esa-filter-bypass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance
(ESA) is affected by following vulnerability

  - A vulnerability in the email message scanning of Cisco
    AsyncOS Software for Cisco Email Security Appliance
    (ESA) could allow an unauthenticated, remote attacker to
    bypass configured content filters on the device.The
    vulnerability is due to improper input validation of the
    email body. An attacker could exploit this vulnerability
    by inserting specific character strings in the message.
    A successful exploit could allow the attacker to bypass
    configured content filters that would normally drop the
    email. (CVE-2019-1831)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-esa-filter-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?911278c6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo01349");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo78686");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-20190417-esa-filter-bypass");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1831");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  '11.1.0.131',
  '11.1.2.023',
  '12.0.0.208'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['display_version'],
'bug_id'   , 'CSCvo01349, CSCvo78686'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
