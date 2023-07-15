#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/04/27. Deprecated by sambar_cgi_path_disclosure.nasl.

include('compat.inc');

if (description)
{
  script_id(105359);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_bugtraq_id(99534);
  script_cve_id("CVE-2017-7529");

  script_name(english:"nginx < 1.13.3 Integer Overflow Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecataed.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated since it duplicates plugin ID 118151");
  # http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12a2e3b9");
  # https://puppet.com/security/cve/cve-2017-7529
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a93efaaf");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7529");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx"); 
  exit(0);
}

exit(0, 'This plugin has been deprecated. Use sambar_cgi_path_disclosure.nasl (plugin ID 118151) instead.');

