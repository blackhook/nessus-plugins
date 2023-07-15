#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101773);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-11103");
  script_bugtraq_id(99551);

  script_name(english:"Samba 4.4.x < 4.4.15 / 4.5.x < 4.5.12 / 4.6.x < 4.6.6 KDC-REP Service Name Validation (Orpheus' Lyre)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by a service impersonation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.4.x prior to
4.4.15, 4.5.x prior to 4.5.12, or 4.6.x prior to 4.6.6. It is,
therefore, affected by a logic flaw in the Heimdal implementation of
Kerberos, specifically within the _krb5_extract_ticket() function
within lib/krb5/ticket.c, due to the unsafe use of cleartext metadata
from an unauthenticated ticket instead of the encrypted version stored
in the Key Distribution Center (KDC) response. A man-in-the-middle
attacker can exploit this issue to impersonate Kerberos services. This
can potentially result in a privilege escalation or the theft of
credentials. Note that Samba versions built against MIT Kerberos are
not impacted by this issue.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2017-11103.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.4.15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.5.12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/samba-4.6.6.html");
  script_set_attribute(attribute:"see_also", value:"https://www.orpheus-lyre.info/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.4.15 / 4.5.12 / 4.6.6 or later.

Alternatively, if you are not running Samba as an Active Directory
domain controller, as a workaround, you can rebuild Samba using the
following command : ./configure --with-system-mitkrb5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[4-6])?$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# Note versions prior to 4.4 are EoL
# 4.4.x < 4.4.15
# 4.5.x < 4.5.12
# 4.6.x < 4.6.6
if (version =~ "^4\.4\.")
  fix = '4.4.15';
else if (version =~ "^4\.5\.")
  fix = '4.5.12';
else if (version =~ "^4\.6\.")
  fix = '4.6.6';

if ( !isnull(fix) &&
     (ver_compare(ver:version, fix:fix, regexes:regexes) < 0) &&
     (ver_compare(ver:version, fix:'4.0.0', regexes:regexes) >= 0) )
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
