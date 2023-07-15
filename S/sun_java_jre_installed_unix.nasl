#TRUSTED 57b506f510a4d1d6f524fccadd652e00e79bfbbbc072f4a09af1125805fe58dba2efd4024dc54707b52d2f272bc377e640ff631c38635e3c9d72b7c82079c22d81992e3a0ee7d98e745471e92ae52022bbe70872b98d20961cb601ee066d96048514934df012a9c6ef8b8de6f8d1828180053a7785f0f2dd143dcd87b00bfcf588c4d5dec5bf13004d4454052a6749bfdab7c99661885ef5a108e483cb99d1372d4592d737c3572dbb73c8fff91c52e14376a1e82a6c481e638230b136b26f205f88dd40b61bdb655465f1046a9f5ce57f8734c002a1a6381c719e2dc5f3e493d2737d165d043d04089631a341d147f74318b820b750d720e500d52105122db57bb5edb6f6cf07bbd0596511ea4517518dfcc0ea758d24c03c77e5842827da782413d43aa939f3cec4f70bd5faf8925534aada619219310d1b9eb7c7be829f459599ca973b7c3b0bfb555d65558c7a3fe90d6c11e3f33c254ee6d92cc55bb3818e2fbf2bd449eea46430a48eafc475624a6b0b8ac96903375f0fbb956c3da59f5ea844534cc11e45ba394100c47aa86aabb9d9bddf4510cf8722757201845a43bbf7ab7c28035ee6fffb2c1974e81ac17861fa47c4ae1ff17454f60dcd5d020a389483a98b8e70e10108d5e6efbdc4be1d2ebbc6ce6c20a5616c80b1ddea982263d5f1da7924e47ed29a9d5064bde8991adba745373fbc353cdc1d0e6307fb32
#TRUST-RSA-SHA256 5b73b3cf37994ac2b10462080a41cbf4c4215d843621002f649f73aaa280a6c8a65393d7d829a152554cc630be5c53d4876346a1b36b9b01f76600b1f918b1ced58831440bc94fca84f00cd7b28f4cdf8a748c0faedf62d5dad9234262f4bab6c4a836bdf15a719e8738ad35c2b51c905b36c91e73d55e92f40c9be2fec765374f45fdead7a85e364c433b1dccb82fa5d47ffa9ad91a1992d0e64cd209a1d9970dbd4a5d6ee4db5b50ab38c118a72987a3ce87a4a4d5df7836130ba0e15785916d0b868b872ea36568da3ef3ac60fc77ae86711185c8d37fddd10600dcfbee94af708d6b76219439a5e8e5e4762dbeb50fe38c6b34d68df73fb41407df69c018b248ef93c43d458451ad7d6a36eb9741c5166789c02cf68913d6d625701af6e45e1494a9f4cd644fa931fd58fa579f418667bb2c3875c874928ca133aab9e3bf3e96772810a8c65cef085867b91a99dcca771e418dafabd06070c98c9c033013a7abc9e12a5f872d453682c7e187a6c209de48e98b939d1e4f6167e2bd9bf1cfa6364dce8ab3aa71f9834908cd6caa0818273cb8399ad294ed06486d98513364234c7a71c69cd1e52d7c8e6517bbc8745b326b33240a942dbd483feb20272cb8a3382ac0ad304bc02d5791d1c55720b0dbd3cc586568a29e1cec355ee0fd86dd793758184fe85374f10a04ee9d949d05a4a5bd912e7f449baeed1576d215dbfb
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");


if (description)
{
  script_id(64815);
  script_version("1.115");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_xref(name:"IAVT", value:"0001-T-0690");

  script_name(english:"Oracle Java Runtime Environment (JRE) Detection (Unix)");
  script_summary(english:"Checks for Oracle/Sun JRE installs.");

  script_set_attribute(attribute:"synopsis", value:
"The Java runtime environment is installed on the remote Unix host.");
  script_set_attribute(attribute:"description", value:
"One or more instances of Oracle's (formerly Sun's) Java Runtime
Environment (JRE) are installed on the remote host. This may include
private JREs bundled with the Java Development Kit (JDK).

Notes:

  - Addition information provided in plugin
    Java Detection and Identification (Unix)

  - To discover instances of JRE that are not in PATH, 
    or installed via a package manager, thorough tests 
    must be enabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("java_jre_installed_unix.nbin", "linux_process_information.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("install_func.inc");

app = "Oracle Java";
cpe = "cpe:/a:oracle:jre";
prod_name1 = "Oracle Java";
prod_name2 = "Sun Java";
related_app = "Java";

##
#  Note: Several instances of Java may have been found.
#        The plugin is intended to branch/fork here
##
found_java = get_single_install(app_name:related_app);

app_found = FALSE;
if (!empty_or_null(found_java['Application']) &&
    (found_java['Application'] == prod_name1 || found_java['Application'] == prod_name2))
  app_found = TRUE;

if (!app_found)
  exit(0, "The Java instance detected does not appear to be " + app);

path = found_java['Report Path'];
version = found_java['version'];
display_version = found_java['display_version'];
managed = found_java['managed'];
bin_locs = found_java['Binary Location'];

##
#  Correct formatting (downstream plugins have fewer
#   labels than main Java Detection plugin)
##
if ('\n                     ' >< bin_locs)
  bin_locs = str_replace(string:bin_locs, find:'\n                     ', replace:'\n                    ');

# Include any important notes
report = NULL;

# This happens in only one particular situation on RedHat
#  but to be safe, include the exception check here
if (!empty_or_null(found_java['management_uncertain']))
{
  report +=
  'This Java install is likely to be managed. However, '+
  '\n                    ' + 'if it is not, please verify that the version is up-to-date.';
}

# This happens frequently
if (!empty_or_null(found_java['ps_reported']))
{
  report +=
  'This install was discovered by checking the currently'+
  '\n                    ' + 'running processes on the system, and it may not always'+
  '\n                    ' + 'be reported in future scans.';
}

extra = make_array();
extra['Binary Location'] = bin_locs;

if (!empty_or_null(report))
  extra['Details'] = report;

if (managed)
  extra['Managed by OS'] = "True";

extra_no_report = make_array();
extra_no_report['Managed'] = managed;
extra_no_report['version_with_one'] = found_java['version_with_one'];
extra_no_report['version_without_one'] = found_java['version_without_one'];


register_install(
  app_name:app,
  vendor : 'Oracle',
  product : 'JRE',
  path:path,
  version:version,
  display_version:display_version,
  cpe:cpe,  
  extra_no_report:extra_no_report,
  extra:extra
);

report_installs(app_name:app);


exit(0);

