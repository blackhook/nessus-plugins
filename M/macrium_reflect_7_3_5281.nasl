##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142032);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2020-10143");
  script_xref(name:"IAVB", value:"2020-B-0062");

  script_name(english:"Macrium Reflect < 7.3.5281 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"Macrium Reflect installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Macrium Reflect installed on the remote Windows host is prior to version 7.3.5281. It is, therefore, 
affected by a privilege escalation vulnerability related to the OpenSSL component. An unprivileged Windows user can
exploit this, by creating the appropriate path to a specially-crafted openssl.cnf in order to execute arbitrary code
with SYSTEM privileges.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/760767");
  script_set_attribute(attribute:"see_also", value:"https://updates.macrium.com/reflect/v7/v7.3.5281/details7.3.5281.htm");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Macrium Reflect version 7.3.5281 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macrium:reflect");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macrium_reflect_win_installed.nbin");
  script_require_keys("installed_sw/Macrium Reflect", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Macrium Reflect', win_local:TRUE);

constraints = [
  { 'fixed_version' : '7.3.5281' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
