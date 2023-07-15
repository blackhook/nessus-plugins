#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100955);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/06/21 19:36:56 $");

  script_name(english:"AgileBits 1Password 6.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of AgileBits 1Password.");

  script_set_attribute(attribute:"synopsis", value:
"A password management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of AgileBits 1Password installed on the remote Windows
host is equal or prior to 6.3.3. It is, therefore, affected by
multiple vulnerabilities :

  - A security weakness exists in the internal web browser
    in which the default protocol that is used is set to
    HTTP. If a user visits a website without specifying the
    full URL, the more secure HTTPS protocol will not be
    used even if it is available. A man-in-the-middle
    attacker can exploit this to disclose sensitive
    information. (SIK-2016-039)

  - A security weakness exists in the database of the
    password manager due to lack of encryption for titles
    and URLs. An attacker who is able to obtain a copy of
    the encrypted database can exploit this to disclose the
    websites for which the user has stored credentials
    without having to break the cryptography. (SIK-2016-040)

  - A security weakness exists in the password manager due
    to sending the target domain to the vendor's web server
    in order to obtain from a server-side cache an icon that
    represents the respective target website. This issue
    allows the vendor to track all the sites for which the
    user has created database entries. (SIK-2016-042)");
  # https://www.theregister.co.uk/2017/02/28/flaws_in_password_management_apps/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eedc9d32");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-039/");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-040/");
  script_set_attribute(attribute:"see_also", value:"https://team-sik.org/sik-2016-042/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of AgileBits 1Password that is later than 6.3.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:agilebits:1password");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("agilebits_1password_installed.nbin");
  script_require_keys("installed_sw/1Password", "SMB/Registry/Enumerated");

  exit(0);
}


include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"1Password", win_local:TRUE);

constraints = [
  { "equal" : "6.3.3", "fixed_display": "See Solution" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
