#TRUSTED 9fa31067727eb41d0fc52d32cb4901f53ae2d73ea3a84487306f00935157d213e9326f2e9ef89ed8345ddd744891319e4358f66281faf31455ee2fdcf89735e58bd59f11040c40106619ae0d5cfb502314f6a879aa1574c7c3e6ba402ba166e51fb93f3e8ca94718c9958d43afa157a274069b6482638f86416c5a26645ffa8888e09d1d9572f5f0574e8074b36d5af9f2e245c81b86315625549f411f1fc57f3156f3c6b04ca6f0195102a8e95695a1f3c368ed1ca6772fdfe5c8dc33e9bb66d5ad66da4e4a6e4dd5f4b9b86d6e6a6ba446876458f6e5972917c756171a5d24021841bb65af1ca735a48b1326af8ed9dcc9b450818f7b7e5bf9d87c9e9588d22ec8b87c6725fb12e365c66e3590538cf27b49b3ab1801dab065cd4227eee88433f71392e5f484080b6634f31ee7007df7654b351c854cdbda1cc9e12cac197594d8f2e6e133a2c139af908d2405be95ea5406233b4a0108e6b003780b9bc9f91b8f3b95734a8ca873675744dbbaf1eae9dd30fb51a7cd9c60a2363c07280a4b3530c2be8d45070db037dc668efef0a7e3cb0f24ce74fbb2ab00608361784461decf8fadf5d32c2b78523f2bfe270ab7007b12aa3f0cc718272d70844216efd0689fdf43631918c1cc7f74838fa01e712b2c3f35ce3a01cb42383dabe10ec236bec54c11ed766c91ffb68d3c80aa0669ee5890a525d85b75bf9a2bf18425de31
#TRUST-RSA-SHA256 625273b149cc2d4dd87e251af8ae55d9f7636721eed8dd46298e8baa10caddd2e698f3d68588a6f50650a7bce45a0e2fc85e5ef43ee2efd5e3af91092154f63b294f6d0e72b60aa4512c26fd7f9536b97af6f304f6c4b0ea398632cbd716f72c3927ed09bff9526ae5693d3c60cf67c32f32933eaf0663582489240b89a4ffae914a86338ad18418d71e1f9f5efb8f49acfb78779f68d791cd9f6f78de0cdce1cbf0d1819442cb0d2cbe9919f198912b66211ed552965ac1287d4af0623eaa710095819bc857c855f2a180a1690fba1188c3e22cc10c3c42fac2f6c10b0501b20507734761f9b58dbc0323d61c274dccab3f43b138dd1cc1f03a0eff0b836b06ad587664f33e05d096c39c01c18a49de7890b8b68df6a1081b0a7b6af247c51952ca147f71d73af8d970691f0e9be6ad567ea9025949b4e3dcc3981f8fead25ef95c3d588adfd77c349468c200f096de9e81a117aa27db2a196a673b2b1be48ac9fe62a425b0bb2a8d1fb2cb79fb31936ced31e000e5230adbdc6ecf7d32623bee80b1ea7038188b81d08a4070e29893a4deb4c9a1135a50feb2e851f34376b3f009e58e8d24c44bdda94357d977ea9c6c4f7128a8f6e5dd6a1f2f37232fa617cfb89751cbc40cca23c53e19140cd0b199ff5d7516d3ab3c8639b4cdcf6ddcc5a8d88f94f876399687ad23748de8fe66bac090025c7d0c6a828cc95dcca605e7
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(171013);
 script_version("1.0");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/06");

 script_name(english:"Scan Search settings");
 script_summary(english:"Search settings.");

 script_set_attribute(attribute:"synopsis", value:
"Sets search settings.");
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous search variables for Nessus
plugins. It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/06");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 exit(0);
}

include("debug.inc");
include("win_paths.inc");

var data, kb_name, kb_value, path, paths, inclusions, modified_inclusions, exclusions, item;

inclusions = [];
exclusions = [];
kb_name = 'Host/windows_search_options/filepath_inclusions';
# Gather windows path include values
data = get_one_kb_item("TEST_FLATLINE/windows_search_filepath_inclusions");
if (empty_or_null(data) && !empty_or_null(get_preference("Scan Search settings[file]:windows_search_filepath_inclusions")))
{
  data = get_preference_file_content("Scan Search settings[file]:windows_search_filepath_inclusions");
}

if (empty_or_null(data))
{
  dbg::detailed_log(lvl:1, msg:'No user supplied filesystem inclusions found.');
  replace_kb_item(name:kb_name, value:FALSE);
  # Skip rest of giant else block
}
else
{
  dbg::detailed_log(
    lvl:1,
    msg:'User supplied filesystem inclusions found',
    msg_details:{
       'Includes':{"lvl":3, "value":'\n' + data}
    });
  paths = split(data, keep:FALSE);
  foreach path (paths)
  {
    # Remove forbidden characters
    item = local_detection_win::filepath_remove_forbidden(item:path);
    if (item != path)
      dbg::detailed_log(
        lvl:1,
        msg:'Invalid character(s) supplied in path has/have been removed',
        msg_details:{
           "Original":{"lvl":1, "value":path},
           "Modified":{"lvl":1, "value":item}
        });
    append_element(var:inclusions, value:item);
  }
  # Remove redundant includes
  inclusions = local_detection_win::filepath_list_trim(paths_to_check:inclusions, paths_to_exclude:inclusions);
  kb_value = serialize(inclusions);
  replace_kb_item(name:kb_name, value:kb_value);
  dbg::detailed_log(
    lvl:1,
    msg:'Processed user supplied filepath inclusions',
    msg_details:{
       "Includes":{"lvl":3, "value":kb_value}
    });
}


kb_name = 'Host/windows_search_options/filepath_exclusions';
# Gather windows path exclude values
data = get_one_kb_item("TEST_FLATLINE/windows_search_filepath_exclusions");
if (empty_or_null(data) && !empty_or_null(get_preference("Scan Search settings[file]:windows_search_filepath_exclusions")))
{
  data = get_preference_file_content("Scan Search settings[file]:windows_search_filepath_exclusions");
}

if (empty_or_null(data))
{
  dbg::detailed_log(lvl:1, msg:'No user supplied filesystem exclusions found.');
  replace_kb_item(name:kb_name, value:FALSE);
  # Skip rest of giant else block
}
else
{
  dbg::detailed_log(
    lvl:1,
    msg:'User supplied filesystem exclusions found',
    msg_details:{
       'Excludes':{"lvl":3, "value":'\n' + data}
    });
  paths = split(data, keep:FALSE);
  foreach path (paths)
  {
    # Remove forbidden characters
    item = local_detection_win::filepath_remove_forbidden(item:path);
    if (item != path)
      dbg::detailed_log(
        lvl:1,
        msg:'Invalid character(s) supplied in path has/have been removed',
        msg_details:{
           "Original":{"lvl":1, "value":path},
           "Modified":{"lvl":1, "value":item}
        });
    append_element(var:exclusions, value:item);
  }
  # Remove redundant excludes
  exclusions = local_detection_win::filepath_list_trim(paths_to_check:exclusions, paths_to_exclude:exclusions);
  kb_value = serialize(exclusions);
  replace_kb_item(name:kb_name, value:kb_value);
  dbg::detailed_log(
    lvl:1,
    msg:'Processed user supplied filepath exclusions',
    msg_details:{
       "Excludes":{"lvl":3, "value":kb_value}
    });
}

# Remove includes that are already excluded
if (!empty_or_null(inclusions) && !empty_or_null(exclusions))
{
  modified_inclusions = local_detection_win::filepath_list_trim(paths_to_check:inclusions, paths_to_exclude:exclusions, exclude_identical:TRUE);
  if (len(modified_inclusions) != len(inclusions))
  {
    kb_name = 'Host/windows_search_options/filepath_inclusions';
    if (empty_or_null(modified_inclusions))
    {
      dbg::detailed_log(lvl:1, msg:'All supplied filesystem inclusions removed by supplied filesystem exclusions.');
      replace_kb_item(name:kb_name, value:FALSE);
      replace_kb_item(name:'Host/windows_search_options/filepath_include_exclude_paradox', value:TRUE);
    }
    else
    {
      kb_value = serialize(modified_inclusions);
      replace_kb_item(name:kb_name, value:kb_value);
      dbg::detailed_log(
        lvl:1,
        msg:'User supplied filepath inclusions with user supplied filepath exclusions removed',
        msg_details:{
           "Includes":{"lvl":3, "value":kb_value}
        });
    }
  }
}
