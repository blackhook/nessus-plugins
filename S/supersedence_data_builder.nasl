#TRUSTED 8b4b53b64c588ff93815023ba31eb0c88bdb64f7a5f1e70bbbbd7a41417481ecf884cea16bbc4de34b4db7bd414b7784336d52cd58a255c97ce104ebe5d0d82d2ae38fec9caca4f26ae7b3fff4fda40d36fef097f0cde76fe8064d6f3110923f7be82acd5ef33b23f3ad77c4fb93ffc7a73960e055f838939740bd88bbf45a41f6266798c78cdcfab99d45555ade4ae3cc56eea4241aefb046258529083d09d36e38645bfd99ba24e93e9a9c16ccf50de43e07541b99ff16c00442207be36f64bab58cdd433acf28423712b921041de4c54cba56b5a5d04310586478d1c599126c852202764ea2f4e4b67d16d0e54e72198744607f61352efcb1a2af4c865dca5a104a6e63771c7a9016a8ebbd6017f27d0a6197622dcff328efce196983493558c9e5467be578d2013c69cb7d2eb8d373e242ac7b222d4e5df92d02f29d061dadd1d368a91e115f760f3426dc10c40a718b7f4a306b96d4141c1245db7399e0c9b5f9d2ba4bbfa48525460d86cb0b869188f999197b4c7fa94a0452271f3619ef27db19172c273bc462d70ff7c497a2582ea23a5bb6d1204ac81f01a92fde8730a15184c324da7028a273acb44cf292e062844fc114b54097b6f0ad354c8e1ecaa2e8f1ed2af3602bdec997ad9cc983031823e01f83b51f0c754de929d111deb58cdb9759394ece8cde622f08301b164f169bbfd5355f749c869fdbae92d6ad

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(161455);
 script_version("1.6");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/06");

 script_name(english:"Supersedence Data Builder");
 script_summary(english:"Builds a table of supersedence data used to determine what is reported.");

 script_set_attribute(attribute:"synopsis", value:"Supersedence data.");
 script_set_attribute(attribute:"description", value:
"Collects and stores supersedence patch data for various patch types.");
 script_set_attribute(attribute:"solution", value:"N/A");
 
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 script_category(ACT_END2);
 script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");
 script_exclude_keys("Host/dead");

 exit(0);
}

include('global_settings.inc');
include('spad_log_func.inc');
include('supersedence_builder.inc');

if (get_kb_item("Host/dead")) exit(0, "The remote host was found to be dead.");

if (!can_query_report()) exit(1, 'Can\'t run query_report().');

if (!supersedence::any_patch_types_available()) exit(0, "No supported patch types found.");

var DEBUG = get_kb_item('global_settings/enable_plugin_debugging');
var found_patch_data = FALSE;
var report = 'Supersedence patch data summary :\n';

# Gather and store patch supersedence data for each patch type.
foreach var patch_type (keys(supersedence::patch_types))
{
  spad_log(name: supersedence::log_name, message:'Gather and store ' + patch_type +' patch supersedence data.');
  if (typeof(supersedence::patch_data_functions[patch_type]) == 'function')
  {
    cnt = supersedence::patch_data_functions[patch_type](type: patch_type);
    if (cnt)
    {
      found_patch_data = TRUE;
      spad_log(name: supersedence::log_name, message:'Inserted ' + cnt + ' ' + patch_type + ' patches.');
    }
    else
    {
      spad_log(name: supersedence::log_name, message:'No ' + patch_type + ' values found.');
    }
    report += '  - ' + patch_type + ' : ' + cnt + '\n';
  }
  else
  {
    spad_log(name: supersedence::log_name, message:'Patch type (' + patch_type + ') data function not defined.');
  }
}

if(!found_patch_data)
{
  report = 'No patch supersedence data found.';
}

var port = 0;

if (DEBUG)
{
  var log = spad_log_get_script_report_attachment(name: supersedence::log_name);

  if (!isnull(log))
  {
    report += '\n\nPlugin debug log has been attached.';
    security_report_with_attachments(
     port        : port,
     level       : SECURITY_NOTE,
     extra       : report,
     attachments : log
    );
    exit(0);
  }
  else
  {
    report += '\n\nUnable to retrieve plugin debug log "' + supersedence::log_name + '".';
    security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
  }
}