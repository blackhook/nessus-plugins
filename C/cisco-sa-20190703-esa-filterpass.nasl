#TRUSTED 23b448b091c8f91eebfcc8c60111651716e0cfa26748fd03db760fb7c93cc65309608adb2c07dec229af7859d7221010354fc3008aa8d1624b85463cee1719ff58bb1aa24b24e3a6ac70af22a6404039fefb3110d7e7adda1a08dc3d444f07821a2fb7614222479801a4d4aef77a0983c077aa7f20d8dfa281aa877840c47794535fcfe17d0903892f9f4b06c4dc12842bcc9c2f780b0ec6e233906801bbf8266dd18693775f33e4c135691266d4ec4f76fc1bf7fc0b5a593d47391532ac129752c9db758ce4a64bff6d393d51b0e52cfb3d801b7c6754ffe0a8c107119eddceeb8318a2f1e1119de2939057d7ab5b032128aa64fc7c114e6284519a9eb6691114ca9112a53e21dc755a51a5d373db8cc8bcfad4839cd2943811384ff1fa6951be0f25f8a5586e179fac1069a6339352e812a9bc74f39b593cd7f7307d01478f5c781b0587c963f26246513b18364b02ee5728f1ee581194b12ca7daddd4ab5c91482ca53c50e7eabbe526b8eff99f0aa8cca8334b74bddfcadc0003c361bb4e70927ebcf95d600d60e6f2f715475180c33a9df12f37887d8d305542866b44967d297422dfbcb1f52def684e9c61b9fd9b6708becd235df6a581e5f9b2d0a4533858b29967336aca657eb68cdb55cb9daa9e893a8653efe6340999fda8dbd4427c86d28f51f8227b443afc746a29a165ea7a8f77c59459b1890691b113b90db0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128034);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1933");
  script_bugtraq_id(109031);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo55451");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-esa-filterpass");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (cisco-sa-20190703-esa-filterpass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by a vulnerability in the email message
scanning of Cisco AsyncOS Software due to improper input validation
of certain email fields. An unauthenticated, remote attacker can
exploit this vulnerability by sending a crafted email message to a
recipient protected by the ESA. A successful exploit allows the
attacker to bypass configured message filters and inject arbitrary
scripting code inside the email body. The malicious code is not
executed by default unless the recipient's email client is configured
to execute scripts contained in emails.

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-esa-filterpass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e665db4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo55451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvo55451.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1933");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

version_list=make_list(
  '10.0.2-020',
  '11.1.2-023'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo55451'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
