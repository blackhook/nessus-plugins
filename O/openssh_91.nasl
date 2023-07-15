#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2022/11/18. Deprecated due to non-exploitable conditions.
##

include('compat.inc');

if (description)
{
  script_id(166612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_name(english:"OpenSSH < 9.1 Multiple Vulnerabilities (deprecated)");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"Plugin has been depreciated: None of the issues found in OpenSSH just prior to 9.1 are believed to be exploitable.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.1");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vulnerability by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}
exit(0, 'This plugin has been deprecated. None of the issues found in OpenSSH just prior to 9.1 are believed to be exploitable..');