#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78827);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCur01959");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140926-bash");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco ASA Next-Generation Firewall GNU Bash Environment Variable Handling Command Injection (cisco-sa-20140926-bash) (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote security device is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"The remote ASA Next-Generation Firewall (NGFW) host is missing a
security patch. It is, therefore, affected by a command injection
vulnerability in GNU Bash known as Shellshock. The vulnerability is
due to the processing of trailing strings after function definitions
in the values of environment variables. This allows a remote attacker
to execute arbitrary code via environment variable manipulation
depending on the configuration of the system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df19d2c1");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140926-bash.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:adaptive_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA-CX/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/ASA-CX/Version');
fix = '9.3.2.1(9)';

# Versions 9.1.x, 9.2.x, and 9.3.x blow 9.3.2.1 (9) are vulnerable
if (
  cisco_gen_ver_compare(a:ver, b:"9.1.0") >= 0 &&
  cisco_gen_ver_compare(a:ver, b:fix) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'ASA CX/NGFW', ver);
