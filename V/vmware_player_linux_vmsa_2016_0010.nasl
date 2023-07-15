#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92944);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2016-5330");
  script_bugtraq_id(92323);
  script_xref(name:"VMSA", value:"2016-0010");

  script_name(english:"VMware Player 12.1.x < 12.1.1 Shared Folders (HGFS) Guest DLL Hijacking Arbitrary Code Execution (VMSA-2016-0010) (Linux)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote host is 12.1.x
prior to 12.1.1. It is, therefore, affected by an arbitrary code
execution vulnerability in the Shared Folders (HGFS) feature due to
improper loading of Dynamic-link library (DLL) files from insecure
paths, including the current working directory, which may not be under
user control. A remote attacker can exploit this vulnerability, by
placing a malicious DLL in the path or by convincing a user into
opening a file on a network share, to inject and execute arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player 12.1.1 or later.

Note that VMware Tools on Windows-based guests that use the Shared
Folders (HGFS) feature must also be updated to completely mitigate the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DLL Side Loading Vulnerability in VMware Host Guest Client Redirector');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_require_keys("Host/VMware Player/Version");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

var app = "VMware Player";
var app_info = vcf::get_app_info(app:app);

var constraints = [{'fixed_version' : '12.1.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

