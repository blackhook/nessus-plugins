#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122057);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2008-3789");
  script_bugtraq_id(30837);

  script_name(english:"Samba 3.2.x < 3.2.3 Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is prior to
3.2.3. It is, therefore, affected by a privilege escalation 
vulnerability. An unauthenticated, remote attacker can exploit this 
to gain privileged or administrator access to the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2008-3789.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3789");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

constraints = 
[
  {"min_version" : "3.2.0", "fixed_version" : "3.2.3"}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_NOTE, strict:FALSE);
