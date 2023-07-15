#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83474);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-0538");
  script_bugtraq_id(74426);
  script_xref(name:"CERT", value:"581276");

  script_name(english:"EMC AutoStart < 5.5.0 HF4 ftAgent Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the EMC AutoStart ftAgent that
is affected by a remote code execution vulnerability due to a failure
to communicate securely between nodes. An unauthenticated, remote
attacker can exploit this, via specially crafted packets, to execute
arbitrary commands on the remote host with root or SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/581276/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC AutoStart 5.5.0.508 (HF4).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:autostart");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("emc_autostart_ftagent_version.nbin");
  script_require_keys("emc/autostart/ftagent/version");
  script_require_ports("Services/emc-autostart-ftagent", 8045);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

ver_str = get_kb_item_or_exit('emc/autostart/ftagent/version');
port = get_service(ipproto:'TCP',svc:"emc-autostart-ftagent", default:8045, exit_on_fail:TRUE);

fix = '5.5.0.508';
vuln = FALSE;
version = ver_str;

# lower branches may have a slightly different version format
# so go ahead and flag those (< 5.5) as vuln before trying to fully
# parse version string
if(ver_str =~ "^\s*[0-4]($|[.\s])" || # 0-4.x
   ver_str =~ "^\s*5($|\s|\.[0-4]($|[.\s]))") # 5.0-4.x
{
  vuln = TRUE;
}
else if(ver_str =~ "^\s*5\.5($|[.\s])")
{
  item = eregmatch(string:ver_str, pattern:"^\s*([\d.]+)\s+build\s+([\d]+)");
  if(isnull(item)) audit(AUDIT_VER_FORMAT, ver_str);

  version = item[1] + "." + item[2];

  if (ver_compare(ver:version, fix:fix) == -1) vuln = TRUE;
}

if(vuln)
{
  if(report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "EMC AutoStart ftAgent", port); 
