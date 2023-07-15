#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57365);
  script_version("1.8");
  script_cvs_date("Date: 2018/11/26 11:02:16");

  script_cve_id("CVE-2011-4607");
  script_bugtraq_id(51021);

  script_name(english:"PuTTY Password Local Information Disclosure");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY between 0.59 and 0.61,
inclusive.  Such versions are known to contain an information
disclosure issue, where PuTTY neglects to wipe passwords from memory
that it no longer requires. 

Note that to exploit this vulnerability, a malicious, local process
must have permission to access the memory assigned to the PuTTY
process.");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.62.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4607");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/password-not-wiped.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d29e474b");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

constraints = [
  { "min_version" : "0.59", "fixed_version" : "0.62" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
