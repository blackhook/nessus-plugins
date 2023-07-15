#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101265);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6715", "CVE-2017-6716");
  script_bugtraq_id(99209, 99220);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170621-fmc1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170621-fmc2");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy88951");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy88785");

  script_name(english:"Cisco Firepower Management Center Multiple XSS");
  script_summary(english:"Checks the version of Cisco Firepower Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"A network management application installed on the remote host is
affected by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower Management Center installed on the
remote host is equal or prior to 5.4.1.x. It is, therefore, affected
by multiple stored cross-site scripting vulnerabilities due to
improper validation of user-supplied input before returning it to
users. An authenticated, remote attacker can exploit these, via a
specially crafted request, to execute arbitrary script code in a
user's browser session.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-fmc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81191beb");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-fmc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1386f986");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Firepower Management Center version 6.0.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6716");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower/Version");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

version = get_kb_item_or_exit("Host/Cisco/firepower/Version");

# strip out build
item = pregmatch(pattern:"^([0-9.]+)($|-)", string:version);
if(!isnull(item))
  version = item[1];
else audit(AUDIT_VER_FORMAT, version);

flag = 0;
fixed_version = "";

# Affected : < 6.0
if (version =~ "^[0-5]($|[^0-9])")
{
  flag++;
  fixed_version = "6.0.0";
}

if (flag)
{
  report =
    '\n  Installed Version : ' + version +
    '\n  Fixed version     : ' + fixed_version;
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE, xss:TRUE);
}
else audit(AUDIT_DEVICE_NOT_VULN, "Cisco Firepower System", version);
