#TRUSTED 4df83f08ff62dec858d648f398fac69bf2da06bb8d069d679901050b39dabf126bea15f6d32d9f55d5ccd5686f42419a1d89afd5385ea9dfb445228df67184f9a0d6ee2309e4e0e2b0f9349c54f9cd92df8d5e5e61d480e774aa3448d8d363c044516bd83b152c579e22dc263c71ac287c70820981219df12e442a3c831e534961593beacc7b73cc8130133a0295275f10c8ed9fbcdcbe1fca040e6b8f362694c33505639499dc6dca6d9169d79dbf76a7f830b841a3d945954bf7c48eacdd8178b9dd957f1c4a19ffd340fb3b6552896054372125017927801e704c39681473942b9bfd751d66a480e0ab76d42dbeed641bc72a40133c1d294e444b1d42966628dcafed689098503dfd27bdf21f18ac212f549ed1ca695e31b6a9a18c2e112557c7892f86856230a465766952e07b65b23cac673f502401a4e696c0e98eecb5fa6154fb35d539b59cbc7f584cb70fe416f416b863359c5cad7d77ce0bdd588763a8a31554a46c0ab9a386e177cfd7832b1518b10916fbb01fedd682ce5fc23775d09197dbf73e4908118b0897b34cdcf570000d35f66bd38462c5db38e98437a407dc03e3fcf5ea8a9a180d94b35b7f546a73f6013449336b8d4998d8a931372684cbec510025196a4a1b6e0eadfed4d5bb54081564597b5ad275c4056956752c9a9010777020218cad0878176ed57f7e8289cf592180378fad93d0601c13d3
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if ((!find_in_path("hydra")) && (!file_stat(nessus_get_dir(N_STATE_DIR) + '/feed_build')))
{
  exit(0, "Hydra was not found in '$PATH'.");
}


include("compat.inc");

if(description)
{
 script_id(44915);
 script_version ("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value: "2020/06/12");

 script_name(english: "Hydra Error Summary");
 script_summary(english: "Summarizes errors recorded in KB items");

 script_set_attribute(attribute:"synopsis", value:
"Errors happened during Hydra scan." );
 script_set_attribute(attribute:"description", value:
"This plugin sumarizes any errors that were encountered while running
Hydra. 

If any are reported, results from those plugins may be incomplete." );
 script_set_attribute(attribute:"solution", value:
"Reduce the parallelism in the Hydra options.");
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/02/25");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2010-2020 Tenable Network Security, Inc.");
 script_family(english: "Brute force attacks");
 script_dependencie("hydra_options.nasl");
 script_require_keys("/tmp/hydra/force_run");
 exit(0);
}


####

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}
else report_verbosity = 1;



report = "";
l = get_kb_list("Hydra/errors/*/*");
if (isnull(l)) exit(0, "No Hydra/errors/*/* KB items.");

foreach var k (keys(l))
{
  v = split(k, sep: "/", keep: 0);
  svc = v[2]; port = int(v[3]);
  if (isnull(svc) || port == 0)
  {
    #err_print("Could not parse KB key: ", k);
    continue;
  }
  n = l[k];
  report = strcat(report, 'The module ', svc, ' reported ', n, ' errors on port ', port, '\n');  
  if (report_verbosity > 1)
  {
    txt = get_kb_item("Hydra/error_msg/"+svc+"/"+port);
    if (strlen(txt) > 0)
     report = strcat(report, '--------\n', txt, '--------\n');
  }
  report += '\n';
}

if (strlen(report) > 0)
  security_note(port: 0, extra: report);
