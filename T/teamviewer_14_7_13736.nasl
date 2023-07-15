#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135708);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-18988");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:" TeamViewer Insecure Directory Permissions Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TeamViewer Desktop installed on the remote Windows host
upto 14.7.1965 allows a bypass of remote-login access control where different customers'
used a shared AES key for all installations. Attacker can used the said key to decrypt protected information 
stored in the registry or configuration files of TeamViewer. 
For versions before v9.x , attackers are allowed to decrypt the Unattended Access password to the system (that allows for remote login to 
the system as well as headless file browsing).");
  # https://community.teamviewer.com/t5/Change-Logs/Windows-v14-7-1965-Full-Change-Log/td-p/74586
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97174650");
  # https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d15e443c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 14.7.13736 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18988");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed", "installed_sw/TeamViewer/");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'TeamViewer');

constraints = [{ 'fixed_version' : '14.7.13736' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);