#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81421);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2015-0580");
  script_bugtraq_id(72576);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq79027");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150211-csacs");

  script_name(english:"Cisco Secure Access Control System SQLi Vulnerability (cisco-sa-20150211-csacs)");
  script_summary(english:"Checks the ACS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Secure Access Control System (ACS) running on the
remote host is prior to 5.5 patch 7. It is, therefore, affected by a
SQL injection vulnerability due to not properly sanitizing user input
to the ACS View reporting interface pages. An authenticated, remote
attacker, using crafted HTTP requests, can disclose or modify
arbitrary data in the ACS View databases by injecting or manipulating
SQL queries.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150211-csacs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9cfc99c");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37354");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.5 patch 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0580");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_secure_acs_version.nasl");
  script_require_keys("Host/Cisco/ACS/Version", "Host/Cisco/ACS/DisplayVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/ACS/Version");
display_ver = get_kb_item_or_exit("Host/Cisco/ACS/DisplayVersion");

fix = '5.5.0.46.7';

if ( ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 )
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);

}
else audit(AUDIT_INST_VER_NOT_VULN, 'Secure ACS', display_ver);
