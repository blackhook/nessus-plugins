##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142892);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/19");

  script_cve_id("CVE-2020-12846");
  script_xref(name:"IAVA", value:"2020-A-0532-S");

  script_name(english:"Zimbra Collaboration Server < 8.8.15 P10 / 9.x < 9.0.0 P3 Unrestricted Upload");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by an unrestricted upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, Zimbra Collaboration Server is below 8.8.15 Patch 10, or 9.x prior to
9.0.0 Patch 3. It is, therefore, affected by an unrestricted upload vulnerability in the '/service/upload' servlet. An
authenticated, remote attacker can exploit this, by uploading executable files in the Contact section of the mailbox as
an avatar image for a contact, to upload and store files in '/opt/zimbra/data/tmp/upload/', leaving it open to possible
remote execution.

Note that Nessus does not identify patch level or components versions for the Synacor Zimbra Collaboration Suite. You
will need to verify if the patch has been applied by executing the command 'zmcontrol -v' from the command line as the
'zimbra' user.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/8.8.15/P10");
  script_set_attribute(attribute:"see_also", value:"https://wiki.zimbra.com/wiki/Zimbra_Releases/9.0.0/P3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.8.15 P10, 9.0.0 P3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12846");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zimbra_web_detect.nbin");
  script_require_keys("www/zimbra_zcs", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 7071);

  exit(0);
}

include('http.inc');
include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:443);

app = 'zimbra_zcs';
app_full_name = 'Zimbra Collaboration Server';

vcf::add_separator('_');
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

# Change app name for audit trail
app_info.app = app_full_name;

# We cannot detect patch level, so we need to flag all of 8.8.15 and 9.0.0
constraints = [
  { 'fixed_version' : '8.8.16', 'fixed_display' : '8.8.15 Patch 10' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.1', 'fixed_display' : '9.0.0 Patch 3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING); 
