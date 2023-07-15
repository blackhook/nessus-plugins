#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(95474);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2016-9079");
  script_bugtraq_id(94591);
  script_xref(name:"MFSA", value:"2016-92");
  script_xref(name:"CERT", value:"791496");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Mozilla Firefox ESR 45.x < 45.5.1 nsSMILTimeContainer.cpp SVG Animation RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is 45.x prior to 45.5.1. It is, therefore, affected by a
use-after-free error in dom/smil/nsSMILTimeContainer.cpp when handling
SVG animations. An unauthenticated, remote attacker can exploit this
issue, via a specially crafted web page, to deference already freed
memory, resulting in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-92/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 45.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9079");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'45.5.1', min:'45.0', severity:SECURITY_WARNING);
