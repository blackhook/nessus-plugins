#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133675);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id(
    "CVE-2020-5820",
    "CVE-2020-5821",
    "CVE-2020-5822",
    "CVE-2020-5823",
    "CVE-2020-5824",
    "CVE-2020-5825",
    "CVE-2020-5826"
  );
  script_bugtraq_id(
    111771,
    111773,
    111774,
    111775,
    111776,
    111777,
    111778
  );
  script_xref(name:"IAVA", value:"2020-A-0060-S");

  script_name(english:"Symantec Endpoint Protection Client 14.x < 14.2.5569.2100 Multiple Vulnerabilities (SYMSA1505)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Endpoint Protection Client installed on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed 
on the remote host is 14.x prior to 14.2.5569.2100. It is, therefore, affected by multiple vulnerabilities:

    - A privilege escalation vulnerability exists. An unauthenticated,
      remote attacker can exploit this to compromise the software 
      application to gain elevated access to resources that are 
      normally protected from an application or user. 
      (CVE-2020-5820, CVE-2020-5822, CVE-2020-5823)

    - A DLL injection vulnerability exists. An unauthenticated, local
      attacker can exploit this to execute their own code in place of
      legitimate code as a means to perform an exploit. (CVE-2020-5821)	
 
    - A denial of service (DoS) vulnerability exists. An 
      unauthenticated, remote attacker can exploit this issue to make
      the application stop responding.(CVE-2020-5824)
    
    - An arbitrary file write vulnerability exists. An 
      unauthenticated, remote attacker can exploit this to overwrite 
      existing files on the resident system without proper 
      privileges. (CVE-2020-5825)

    - An out-of-bounds read error exists. An unauthenticated, remote 
      attacker can exploit this to read memory outside of the bounds 
      of the memory that had been allocated to the program. (CVE-2020-5826)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1505.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ad00a7d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version
14.2.5569.2100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5823");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app = 'Symantec Endpoint Protection Client';

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');
if(get_kb_item('SMB/svc/ssSpnAv')) audit(AUDIT_INST_VER_NOT_VULN, 'Symantec.cloud Endpoint Protection');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';
fixed_ver = NULL;

if (display_ver =~ "^14\.")
  fixed_ver = '14.2.5569.2100';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);


if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
