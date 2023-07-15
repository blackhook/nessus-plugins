#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25735);
  script_version("1.22");

  script_cve_id(
    "CVE-2007-3089", 
    "CVE-2007-3285", 
    "CVE-2007-3656", 
    "CVE-2007-3734",
    "CVE-2007-3735", 
    "CVE-2007-3736", 
    "CVE-2007-3737", 
    "CVE-2007-3738"
  );
  script_bugtraq_id(24286, 24447, 24831, 24946);

  script_name(english:"Firefox < 2.0.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Firefox is affected by various security
issues, one of which may lead to execution of arbitrary code on the
affected host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-18/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-19/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-20/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-21/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-22/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-23/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-24/" );
 script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-25/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 2.0.0.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200, 264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/17");
 script_cvs_date("Date: 2018/07/16 14:09:14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'2.0.0.5', severity:SECURITY_HOLE);