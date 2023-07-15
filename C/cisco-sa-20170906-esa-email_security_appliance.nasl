#TRUSTED 5b6a7c05ede325bb1303cc1c6b9875bc7333e38ed7709d55b66a48879a1bb4323043c5f58e5201a5e1545a0cc7accf066be56fc3bd153cae68ab9dfcf88b48bbdf0e4952ca36d8aab970ba9f717073cc61f6a8d5cea18a8c9f5a9bbed7a3d50926338dd34b8e87986e70a10020bc8f3e6e11f67935d23d712672693a9a2be63c7708fef22da9d209a4cd8b2f273ed08103f66945b1c1ca944c550ee7b167c16cc8397b93af1269f28284c3a7371fe237a85343645b0086a02b84d53d23cf163f7df3232cbbaf76248923cc8cbdf9af006083fb7d2041fc89452a61563d9358302b7efb48bb04600d05979a637e85e43fb5eb8434ffae2cab7545f800beb0bf3126465c9af04c1a07462bd95720976f436f59b06b1af25a6b7fd4a09b12d6feab7982e344e3fdec31f0fdc96ccf5be429d30b5dbc468b1850b70c1429183d48290b905cd08ad54a4343bcc7fe129200912e6f19e6413174bbe0aafa4e5df46b0b033b6d32d69a0a8cf8239ec0199741a0c84925643d30af5cce3057cdf700fb94d89c15e232c1fe93cd18c40c67d92fdba4e5056fa29bbde542465cc7a0b6a04894f76ba039cabf51a1572e7d3d5adcbebc0f75d42825aeecf2c73dc6d45b5065d6c1dc40028b9426687dea5545c4d8ba19a4a4f41be346a0fac2a494ac27878a7791e2e3626b982238ccde768c055150b6724b2aafac5cfcea0448325adacc3f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103049);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2017-12218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz81533");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170906-esa");

  script_name(english:"Cisco Email Security Appliance Malformed EML Attachment Bypass Vulnerability (cisco-sa-20170906-esa)");
  script_summary(english:"Checks the Cisco Email Security Appliance (ESA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Email Security Appliance (ESA) is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170906-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bf00827");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz81533");

  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCuz81533.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12218");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");
  script_require_ports("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Email Security Appliance (ESA)");

version_list = make_list(
  "10.0.0.082",
  "8.5.5.280",
  "9.1.0.042",
  "9.6.0.042",
  "9.7.0.125",
  "9.7.1.066"
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , "CSCuz81533",
  'fix'      , "See advisory"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
