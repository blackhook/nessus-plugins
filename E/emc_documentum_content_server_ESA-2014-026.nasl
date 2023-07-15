#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77632);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-0642");
  script_bugtraq_id(66796);

  script_name(english:"EMC Documentum Content Server Information Disclosure (ESA-2014-026)");
  script_summary(english:"Checks for Documentum Content Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC Documentum Content Server
that is affected by an information disclosure vulnerability due to
improper authorization checks. A remote, authenticated user can
exploit this vulnerability to read metadata from folders outside of
restricted folders configured for Content Server users.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2014/Apr/att-71/ESA-2014-026.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_content_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_documentum_content_server_installed.nbin");
  script_require_keys("installed_sw/EMC Documentum Content Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("emc_documentum.inc");

app_name = DOC_APP_NAME;
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

fixes = make_nested_list(
  make_list("7.1P02"),
  make_list("7.0P13"),
  make_list("6.7SP2P13"),
  make_list("6.7SP1P26", DOC_NO_MIN)
);

documentum_check_and_report(install:install, fixes:fixes, severity:SECURITY_WARNING);
