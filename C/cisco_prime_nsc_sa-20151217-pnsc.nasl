#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/07/05. Deprecated along with dropping SSH library support.

include("compat.inc");

if (description)
{
  script_id(87849);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2015-6426");
  script_bugtraq_id(79582);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus99427");
  script_xref(name:"IAVA", value:"2016-A-0003");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151217-pnsc");

  script_name(english:"Cisco Prime Network Services Controller Unauthorized Local Command Execution (cisco-sa-20151217-pnsc)(deprecated)");
  script_summary(english:"Check the version of NSC.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"Nessus has dropped device detection of the now EOL Cisco Prime
Network Services Controller.  This plugin is being deprecated
as a result.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151217-pnsc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73b73f12");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus99427");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_network_services_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_require_keys("Host/Cisco/Prime NSC/version");

  exit(0);
}

exit(0);

