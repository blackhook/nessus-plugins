#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(147219);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2021-27055");
  script_xref(name:"MSKB", value:"4484376");
  script_xref(name:"MSKB", value:"4486673");
  script_xref(name:"MSKB", value:"4493151");
  script_xref(name:"MSFT", value:"MS21-4484376");
  script_xref(name:"MSFT", value:"MS21-4486673");
  script_xref(name:"MSFT", value:"MS21-4493151");

  script_name(english:"Security Updates for Microsoft Visio Products (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing a security update.
It is, therefore, affected by the following vulnerability:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2021-27055)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484376");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486673");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493151");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484376
  -KB4486673
  -KB4493151");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-03';
var kbs = make_list(
  '4484376',  # Visio 2010
  '4486673',  # Visio 2013
  '4493151'   # Visio 2016
);
var severity = SECURITY_WARNING;

var constraints = [
  { 'kb':'4484376',  'fixed_version': '14.0.7266.5000', 'sp' : 2},
  { 'kb':'4486673',  'fixed_version': '15.0.5327.1000', 'sp' : 1},
  { 'kb':'4493151', 'channel':'MSI', 'fixed_version': '16.0.5134.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Visio'
);

