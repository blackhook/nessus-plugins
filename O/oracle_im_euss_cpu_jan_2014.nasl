#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72259);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-5900", "CVE-2014-0391");
  script_bugtraq_id(64829, 64838);

  script_name(english:"Oracle Identity Manager End User Self Service (January 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an identity management application installed that
is affected by multiple, unspecified vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the January 2014 Critical Patch Update for
Oracle Identity Manager.  It is, therefore, potentially affected by
multiple, unspecified vulnerabilities in the End User Self Service
sub-component of Oracle Identity Manager.");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2014 Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("Oracle/OIM/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OIM/Installed");
installs = get_kb_list_or_exit("Oracle/OIM/*/Version");
mwinstalls = make_array();
component = "oracle.jrf.adfrt";

# For this check, we need Middleware home which should be
# oracle_common one directory up
foreach install (keys(installs))
{
  mwohome = install - 'Oracle/OIM/';
  mwohome = mwohome - '/Version';

  mwohome = ereg_replace(pattern:'^(/.*/).*$', string:mwohome, replace:"\1oracle_common");

  # Make sure the component that is being patched exists in
  # the middleware home
  # Change the version of our installs to the version of the component
  # since the patches correspond to the component version. 
  jrf_ver = find_oracle_component_in_ohome(ohome:mwohome, compid:component);
  if (!isnull(jrf_ver))
    mwinstalls[mwohome] = jrf_ver;
}

patches = make_array();
patches['11.1.2.1'] = make_list('17617673');
patches['11.1.2.0'] = make_list('17617673');
patches['11.1.1.6'] = make_list('17617669');
patches['11.1.1.7'] = make_list('17617649');
patches['11.1.1.5'] = make_list('17617673');


# Report as oracle help technologies under OIM to avoid confusion re: ohome version vs component version. 
if (max_index(keys(mwinstalls)) > 0)
  oracle_product_check_vuln(product:'Oracle Help Technologies installed under Oracle Identity Manager', installs:mwinstalls, patches:patches);
exit(0, 'No Middleware Homes were found with the oracle.jrf.adfrt component.');
