##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/11/09. Deprecated due to advisory update.
##
include('compat.inc');

if (description)
{
  script_id(147146);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/10");

  script_cve_id("CVE-2021-1425");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw39308");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-info-disclo-VOu2GHbZ");
  script_xref(name:"IAVA", value:"2021-A-0116-S");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esa-sma-info-disclo-VOu2GHbZ) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated to reflect a revision in the Cisco advisory. Cisco ESA is not vulnerable.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-info-disclo-VOu2GHbZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?365a1f2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw39308");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}
exit(0, 'This plugin has been deprecated due to an update to the corresponding Cisco advisory. Cisco ESA is not vulnerable.');
