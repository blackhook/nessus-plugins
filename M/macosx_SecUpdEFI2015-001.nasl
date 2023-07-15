#TRUSTED 3aaf901d357b707a48622e5d43dc91607524b910095dc5112f751e7777cf2d46f81b3923e5b5352606f086dd05df77b5c3e18eee555ef564846167d6c6e783f93ffb3311d2063556e4e7f3420fb81de96bf55ebd32227102c512777fa385a3c3288315f6e639fac44a868beab4b3bf0f4dd5bfca9f62e6c9db3db4b6385bb894d5ff764f3ab9cea8ee22170b99cb62b98edf5f2363790725da6e1f27c993ee25e9727085cf8af3797a393464c2cabe62410ed92df08e7647d2e49493cea0c6f996ad6aa349a783620a0671271d90fe4df8ab1754a8d929e2160ddc409833cf28d7edab72516b9542986ddd2e4288be123c4b3c50fd0324ebefe67efa878bebbcc87970db7e28e18758cfee5ad1ff75a2abcf69bfb2b9930c72bc5e3d836934f5ac1a5ef31a04edadfb995f4e671e297b4ba92f4f7a0bf432ed5c33b8b6db935fb3d611c1128a4d0a247cca318b61a80766132e704adfa6dec188c705189c1aad44b0d8bb994b8d3177f19bc8d7235f41af0fb1d7f818f8d33bd2997cf77ee304596e3b5d92d953be991542a792025ca4c4c267b8e10ef89763b4eab6fa94c9d4f20d3d7029e601cf265753754e2cad87f82ca537177effafdf2e479dbaf539145b71ce4176f13d260d666ec4387c6649edde6f2d7d6e766cf9dc5035d14d078674c463a8ec51e8837c0b168eafbfa98aad629e77029b1fed16f92084a7ebc2f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84565);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-3692", "CVE-2015-3693");
  script_bugtraq_id(74971);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-06-30-3");

  script_name(english:"Mac OS X Multiple EFI Vulnerabilities (EFI Security Update 2015-001)");
  script_summary(english:"Checks the EFI version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running EFI firmware that is affected by
multiple vulnerabilities :

  - An insufficient locking issue exists, when resuming from
    sleep states, which allows a local attacker to write to
    the EFI flash memory by using an crafted application
    with root privileges. (CVE-2015-3692)

  - A flaw exists due to lax restrictions on memory refresh
    rates, which allows a specially crafted process to
    corrupt the memory of some DDR3 SDRAM devices by
    inducing bit flips in page table entries (PTEs), also
    known as a 'row-hammer attack'. An attacker can exploit
    this to gain elevated privileges by manipulating the
    PTEs. (CVE-2015-3693)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204934");
  script_set_attribute(attribute:"solution", value:
"Install Mac EFI Security Update 2015-001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3693");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

efi_fixes = make_nested_array(
   "Mac-942459F5819B171B",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-FC02E91DDD3FA6A4",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-42FD25EABCABB274",
    make_array(
      "efi-version", "IM151.88Z.0207.B03.1506050728"
    ),
    "Mac-3CBD00234E554E41",
    make_array(
      "efi-version", "MBP112.88Z.0138.B15.1506050548"
    ),
    "Mac-8ED6AF5B48C039E1",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-35C1E88140C3E6CF",
    make_array(
      "efi-version", "MBA61.88Z.0099.B19.1506050547",
      "minimum-smc-version", "2.12f135"
    ),
    "Mac-81E3E92DD6088272",
    make_array(
      "efi-version", "IM144.88Z.0179.B10.1506050729"
    ),
    "Mac-35C5E08120C7EEAF",
    make_array(
      "efi-version", "MM71.88Z.0220.B03.1506051117"
    ),
    "Mac-94245BF5819B151B",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-4BC72D62AD45599E",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-2E6FAB96566FE58C",
    make_array(
      "efi-version", "MBA51.88Z.00EF.B03.1506081623"
    ),
    "Mac-7BA5B2794B2CDB12",
    make_array(
      "efi-version", "MM51.88Z.0077.B12.1506081728"
    ),
    "Mac-031AEE4D24BFF0B1",
    make_array(
      "efi-version", "MM61.88Z.0106.B08.1506081405"
    ),
    "Mac-7DF2A3B5E5D671ED",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-00BE6ED71E35EB86",
    make_array(
      "efi-version", "IM131.88Z.010A.B08.1506081728"
    ),
    "Mac-942B59F58194171B",
    make_array(
      "efi-version", "IM121.88Z.0047.B21.1506101610"
    ),
    "Mac-742912EFDBEE19B3",
    make_array(
      "efi-version", "MBA41.88Z.0077.B12.1506081728"
    ),
    "Mac-189A3D4F975D5FFC",
    make_array(
      "efi-version", "MBP111.88Z.0138.B15.1506050728"
    ),
    "Mac-937CB26E2E02BB01",
    make_array(
      "efi-version", "MBA71.88Z.0166.B06.1506051511"
    ),
    "Mac-4B7AC7E43945597E",
    make_array(
      "efi-version", "MBP91.88Z.00D3.B0B.1506081214"
    ),
    "Mac-E43C1C25D4880AD6",
    make_array(
      "efi-version", "MBP121.88Z.0167.B07.1506051617"
    ),
    "Mac-7DF21CB3ED6977E5",
    make_array(
      "efi-version", "MBA61.88Z.0099.B19.1506050547",
      "minimum-smc-version", "2.13f7"
    ),
    "Mac-C3EC7CD22292981F",
    make_array(
      "efi-version", "MBP101.88Z.00EE.B09.1506081405"
    ),
    "Mac-942B5BF58194151B",
    make_array(
      "efi-version", "IM121.88Z.0047.B21.1506101610"
    ),
    "Mac-06F11F11946D27C5",
    make_array(
      "efi-version", "MBP114.88Z.0172.B04.1506051511"
    ),
    "Mac-9F18E312C5C2BF0B",
    make_array(
      "efi-version", "MBA71.88Z.0166.B06.1506051511"
    ),
    "Mac-94245B3640C91C81",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-6F01561E16C75D06",
    make_array(
      "efi-version", "MBP91.88Z.00D3.B0B.1506081214"
    ),
    "Mac-94245A3940C91C80",
    make_array(
      "efi-version", "MBP81.88Z.0047.B2A.1506082203"
    ),
    "Mac-BE0E8AC46FE800CC",
    make_array(
      "efi-version", "MB81.88Z.0164.B06.1506051617"
    ),
    "Mac-27ADBB7B4CEE8E61",
    make_array(
      "efi-version", "IM142.88Z.0118.B11.1506050547"
    ),
    "Mac-06F11FD93F0323C5",
    make_array(
      "efi-version", "MBP114.88Z.0172.B04.1506051511"
    ),
    "Mac-031B6874CF7F642A",
    make_array(
      "efi-version", "IM141.88Z.0118.B11.1506050727"
    ),
    "Mac-F60DEB81FF30ACF6",
    make_array(
      "efi-version", "MP61.88Z.0116.B15.1506050548"
    ),
    "Mac-77EB7D7DAF985301",
    make_array(
      "efi-version", "IM143.88Z.0118.B11.1506050727"
    ),
    "Mac-FA842E06C61E91C5",
    make_array(
      "efi-version", "IM151.88Z.0207.B03.1506050728"
    ),
    "Mac-F65AE981FFA204ED",
    make_array(
      "efi-version", "MM61.88Z.0106.B08.1506081405"
    ),
    "Mac-C08A6BB70A942AC2",
    make_array(
      "efi-version", "MBA41.88Z.0077.B12.1506081728"
    ),
    "Mac-66F35F19FE2A0D05",
    make_array(
      "efi-version", "MBA51.88Z.00EF.B03.1506081623"
    ),
    "Mac-2BD1B31983FE1663",
    make_array(
      "efi-version", "MBP112.88Z.0138.B15.1506050548"
    ),
    "Mac-AFD8A9D944EA4843",
    make_array(
      "efi-version", "MBP102.88Z.0106.B08.1506081215"
    )
);

# Modeled after check actual patch performs
# if the SMC gets "borked" it reports as "0.000"
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoSMCVersions(actual, intended)
{
  local_var pat, item_actual, item_intended,
            actualMajorVersion, actualMinorVersion,
            actualBuildType, actualBuildNumber,
            intendedMajorVersion, intendedMinorVersion,
            intendedBuildType, intendedBuildNumber;

  # borked version checks
  if(actual == "0.000" && intended == "0.000") return 0;
  if(actual == "0.000" && intended != "0.000") return -1;
  if(actual != "0.000" && intended == "0.000") return 1;

  pat = "^(\d+)\.(\d+)([a-f]{1})(\d+)$";
  item_actual = eregmatch(pattern: pat, string: actual);
  item_intended = eregmatch(pattern: pat, string: intended);

  if(isnull(item_actual) || isnull(item_intended)) return -2;

  actualMajorVersion = int(item_actual[1]);
  actualMinorVersion = int(item_actual[2]);
  actualBuildType = item_actual[3];
  actualBuildNumber = int(item_actual[4]);

  intendedMajorVersion = int(item_intended[1]);
  intendedMinorVersion = int(item_intended[2]);
  intendedBuildType = item_intended[3];
  intendedBuildNumber = int(item_intended[4]);

  if(actualMajorVersion != intendedMajorVersion) return -2;
  if(actualMinorVersion != intendedMinorVersion) return -2;

  if(actualBuildType !~ "^[abf]$" || intendedBuildType !~ "^[abf]$")
    return -2;

  if(actualBuildType < intendedBuildType) return -1;
  if(actualBuildType > intendedBuildType) return 1;

  if(actualBuildNumber < intendedBuildNumber) return -1;
  if(actualBuildNumber > intendedBuildNumber) return 1;

  return 0;
}

# Modeled after check patch performs
# output:
#      -2 if there's an error
#      -1 if actual < intended
#      0 if actual == intended
#      1 if actual > intended
function compareTwoEFIVersions(actual, intended)
{
  local_var actual_array, intended_array,
            actual_minor_version, intended_minor_version,
            actual_major_version, intended_major_version;

  actual_array = split(actual, sep:'.', keep:FALSE);
  intended_array = split(intended, sep:'.', keep:FALSE);

  if(max_index(actual_array) != 5 || max_index(intended_array) != 5)
    return -2;

  if(actual_array[0] != intended_array[0]) return -2;
  if(actual_array[1] != "88Z" || intended_array[1] != "88Z") return -2;

  if(actual_array[2] !~ "^[\da-fA-F]{4}$" ||
     intended_array[2] !~ "^[\da-fA-F]{4}$") return -2;

  # don't know why, but this check is in the patch
  if(actual_array[3][0] =~ "[dD]" || intended_array[3][0] =~ "[dD]")
    return -2;

  actual_minor_version = substr(actual_array[3], 1);
  intended_minor_version = substr(intended_array[3], 1);

  if(actual_minor_version !~ "^[\da-fA-F]{2}$" ||
     intended_minor_version !~ "^[\da-fA-F]{2}$") return -2;

  actual_minor_version = ord(hex2raw(s:actual_minor_version));
  intended_minor_version = ord(hex2raw(s:intended_minor_version));

  actual_major_version = getword(blob:hex2raw(s:actual_array[2]),
                                 pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  intended_major_version = getword(blob:hex2raw(s:intended_array[2]),
                                   pos:0, order:BYTE_ORDER_BIG_ENDIAN);
  
  if(actual_major_version > intended_major_version) return 1;
  if(actual_major_version < intended_major_version) return -1;
  if(actual_minor_version > intended_minor_version) return 1;
  if(actual_minor_version < intended_minor_version) return -1;

  return 0;
}

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Available for: OS X Mountain Lion v10.8.5, OS X Mavericks v10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.[89]\.5([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8.5 or Mac OS X 10.9.5");

board_id_cmd = 'ioreg -l | awk -F \\" \'/board-id/ { print $4 }\'';
efi_version_cmd = 'ioreg -p IODeviceTree -n rom@0 | awk -F \\" \'/version/ { print $4 }\'';
smc_version_cmd = 'ioreg -l | awk -F \\" \'/smc-version/ { print $4 }\'';

results = exec_cmds(cmds:make_list(board_id_cmd, efi_version_cmd, smc_version_cmd));

# these may not be considered an 'error' if host is a VM running on non Apple hardware
if(isnull(results)) exit(0, "Unable to obtain hardware information on remote host.");

if(isnull(results[board_id_cmd]) || results[board_id_cmd] !~ "^Mac-[a-fA-F\d]+$")
  exit(0, 'No valid Mac board ID found.');

if(isnull(results[efi_version_cmd]) || ".88Z." >!< results[efi_version_cmd])
  exit(0, 'No valid Mac EFI version found.');

if(isnull(results[smc_version_cmd]) || results[smc_version_cmd] !~ "^(\d+)\.([\da-f]+)$")
  exit(0, 'No valid Mac SMC version found.');

board_id = results[board_id_cmd];
efi_version = results[efi_version_cmd];
smc_version = results[smc_version_cmd];

if(isnull(efi_fixes[board_id])) exit(0, "The remote host does not have an affected board ID (" + board_id + ").");

efi_fix = efi_fixes[board_id]["efi-version"];
min_smc_ver = efi_fixes[board_id]["minimum-smc-version"];

if(!isnull(min_smc_ver))
{
  if(compareTwoSMCVersions(actual:smc_version, intended:min_smc_ver) < 0)
    exit(0, "SMC version " + smc_version + " is too old to allow update.");
}

res = compareTwoEFIVersions(actual:efi_version, intended:efi_fix);
if(res == -2)
  exit(1, "Error comparing EFI version (" + efi_version + ") to fixed version (" + efi_fix + ").");

if(res >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "Apple EFI", efi_version);

port = 0;

if(report_verbosity > 0)
{
  report = '\n  Board ID              : ' + board_id +
           '\n  Installed EFI version : ' + efi_version +
           '\n  Fixed EFI version     : ' + efi_fix + '\n';
  security_hole(port:port, extra:report); 
}
else security_hole(port);
