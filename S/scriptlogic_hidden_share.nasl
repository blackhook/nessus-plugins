#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11561);
 script_version("1.19");
 script_cvs_date("Date: 2019/07/17 16:36:41");

 script_cve_id("CVE-2003-1122");
 script_bugtraq_id(7476);
 script_xref(name:"CERT", value:"813737");

 script_name(english:"ScriptLogic $LOGS Share Remote Information Disclosure");
 script_summary(english:"Connects to LOG$");

 script_set_attribute(attribute:"synopsis", value:"Sensitive data may be accessed on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote host has an accessible LOGS$ share.

ScriptLogic creates this share to store the logs, but does not
properly set the permissions on it. As a result, anyone can use it to
read or modify, or possibly execute code.");
 script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/11922");
 script_set_attribute(attribute:"solution", value:
"Limit access to this share to the backup account and domain
administrator.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1122");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/04");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");
 script_dependencies('smb_enum_share_permissions.nasl', 'smb_enum_shares.nasl');
 script_require_keys('SMB/share_permissions/enumerated', 'SMB/share_permissions/logs$',
    'SMB/share_permissions/logs$/EVERYONE/Allow');
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");

get_kb_item_or_exit('SMB/share_permissions/enumerated');

share = 'logs$';

share_kb = 'SMB/share_permissions/' + share;
get_kb_item_or_exit(share_kb);
get_kb_item_or_exit(share_kb + '/EVERYONE/Allow');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

info = get_kb_item(share_kb + '/EVERYONE/Allow/Report');

report = 'The "' + share + '" share has allow permissions set for "Everyone"';
if (info) report += ' :\n' + info + '\n';
else report += '.\n';

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
