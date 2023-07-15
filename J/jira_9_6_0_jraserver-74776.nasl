#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/04/06. Advisory updated to state Jira is not affected.
##

include('compat.inc');

if (description)
{
  script_id(172500);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-22970", "CVE-2022-22971");

  script_name(english:"Atlassian Jira < 9.6.0 (JRASERVER-74776) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"Atlassian has determined this vulnerability cannot be exploited, and does not impact Jira because it does 
not use the affected methods from Spring Framework. No action is needed by users to mitigate the threat.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-74776");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22971");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

exit(0, 'This plugin has been deprecated.');
