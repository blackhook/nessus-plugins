#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56039);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_name(english:"Mozilla Thunderbird 3.1.x Out-of-Date CA List");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that may be affected
by an out-of-date certificate authority list.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1.x is earlier than 3.1.13 and
is potentially affected by an out-of-date certificate authority list. 
Due to the issuance of several fraudulent SSL certificates, the 
certificate authority DigiNotar has been disabled in Mozilla 
Thunderbird.");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-34/");

  # https://blog.mozilla.org/security/2011/08/29/fraudulent-google-com-certificate/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abdae5f6");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");


  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.13', min:'3.1.0', severity:SECURITY_WARNING);