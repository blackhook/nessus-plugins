##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145065);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2020-9586");
  script_xref(name:"IAVA", value:"2020-A-0226-S");

  script_name(english:"Adobe Character Animator < 3.3 Stack-Based Buffer Overflow (APSB20-25)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Character Animator installed on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Character Animator installed on the remote Windows host is prior to 3.3. It is, therefore, 
affected by a stack-based buffer overflow condition. An unauthenticated, remote attacker can exploit this 
to cause the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/character_animator/apsb20-25.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08253445");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Character Animator version 3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:character_animator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_character_animator_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Character Animator");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Adobe Character Animator', win_local:TRUE);

constraints = [{'fixed_version' : '3.3'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
