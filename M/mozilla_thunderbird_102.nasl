#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(17605);
 script_version("1.22");
 script_cvs_date("Date: 2018/07/16 14:09:15");

 script_cve_id("CVE-2005-0399");
 script_bugtraq_id(12881);

 script_name(english:"Mozilla Thunderbird < 1.0.2 Browser GIF Processing Overflow");
 script_summary(english:"Determines the version of Mozilla Thunderbird");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The installed version of Thunderbird is affected by multiple
vulnerabilities.  A remote attacker could exploit these issues
to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-17/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-18/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-21/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-25/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"https://www.mozilla.org/en-US/security/advisories/mfsa2005-30/"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Thunderbird 1.0.2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/23");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/03/23");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2005-2018 Tenable Network Security, Inc.");
 script_dependencies("mozilla_org_installed.nasl");
 script_require_keys("Mozilla/Thunderbird/Version");
 exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.0.2', severity:SECURITY_HOLE);