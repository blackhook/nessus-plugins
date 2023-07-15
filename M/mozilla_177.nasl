#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(18065);
 script_version("1.19");

 script_bugtraq_id(
   13211, 
   13216, 
   13229, 
   13230, 
   13232, 
   13233
 );
 if ( NASL_LEVEL >= 2200 ) 
 script_cve_id(
   "CVE-2005-0989", 
   "CVE-2005-1153", 
   "CVE-2005-1154", 
   "CVE-2005-1155",
   "CVE-2005-1156", 
   "CVE-2005-1157", 
   "CVE-2005-1159", 
   "CVE-2005-1160"
 );

 script_name(english:"Mozilla Browser < 1.7.7 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host contains multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of Mozilla contains various security issues that
could allow an attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-33/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-35/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-36/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-37/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-38/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-40/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-41/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla 1.7.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/04/15");
 script_cvs_date("Date: 2018/07/16 14:09:14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:mozilla:mozilla");
script_end_attributes();

 script_summary(english:"Determines the version of Mozilla");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Version");
 exit(0);
}

#

include("misc_func.inc");


ver = read_version_in_kb("Mozilla/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 7 ||
      (ver[1] == 7 && ver[2] < 7)
    )
  )
) security_hole(get_kb_item("SMB/transport"));
