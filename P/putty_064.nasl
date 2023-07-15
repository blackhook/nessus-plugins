#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81669);
  script_version("1.9");
  script_cvs_date("Date: 2019/01/02 11:18:37");

  script_cve_id("CVE-2015-2157");
  script_bugtraq_id(72825);

  script_name(english:"PuTTY < 0.64 Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by multiple
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of PuTTY installed that is prior to
0.64. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to a
    failure to clear SSH-2 private key information from the
    memory during the saving or loading of key files to
    disk. A local attacker can exploit this to disclose
    potentially sensitive information. (CVE-2015-2157)

  - An information disclose vulnerability exists in the
    Diffie-Hellman Key Exchange due to a failure to properly
    handle 0 value keys sent by the server. A
    man-in-the-middle attacker can exploit this to disclose
    potentially sensitive information.");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df5e80bf");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/diffie-hellman-range-check.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?865a825d");
  script_set_attribute(attribute:"see_also", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2157");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

constraints = [
  { "fixed_version" : "0.64" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
