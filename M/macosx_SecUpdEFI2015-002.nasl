#TRUSTED 9e2ad6be9980575e8d2a187de66e318d99b9dc6651cf0af3d16fe3c5891feb5e67affcff2c16ba68272432f3b10af3cd9678ec82b5af96d936af2bfb7d992a056b2f6231b8b2a2c60c519e1296bbb0ed4c2dbd8ea5521d0b528022df413c0bf31edd6e1002e9f48ae329280b34705a030045bfa60e84d51c706bae0b3b3327e268331f73cf2721f6599d82fc6d6e67c0b21c2bd89ec01d1bc30573a4cd83193004893e6bc27d1511546ba9534fa6fc62c7ab8bb1724f2f22a56d076867f5fd3e54c4bf660fbd974a3eb47c05ef67e39c5b2db9862671b928f51fe5b63267094cbc8a8d0fcc5dab14a1b30665e3901bdd185bcfd24e360a88471ba7623febc97337366e18b88ca14a2606646b150b5e4239d0f788a4191b933c7cb7f91c52699db85e394d672e785b2a955e425f8acf9c1e52269634a5e3bb8f4d7b3730d7dbe78aea52aef02f7feea0a858f7b57c7a7748d27fe0e05de294f638b78d94cbb7a376f8ef099b2adba00755be13ceed305151bf069f178a5aac061aca0f7448e8ad815fbec64cfb4acfdb9cca960e09b4c00e57bf32390732eac6638a2b710c5a4b65e61739ab65ff97b100a02f7dfbb39ec2ea05e9024d5c95239ebe131937e91d9199a62d8a0bc910e49b6788afbb8b600cdd3e02efa9aa24dc5ec63003ffa8a323d80dcb17b9f428e2d91ae0bbc8d3466d440621f38dbf9989d62775568961f2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86722);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-7035");
  script_bugtraq_id(74971);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-6");

  script_name(english:"Mac OS X EFI Function Execution Vulnerability (EFI Security Update 2015-002)");
  script_summary(english:"Checks the EFI version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a function execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running an EFI firmware version that is
affected by a function execution vulnerability due to an issue with
handling EFI arguments. An unauthenticated, remote attacker can
exploit this to execute arbitrary functions via unspecified vectors.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205317");
  # https://lists.apple.com/archives/security-announce/2015/Oct/msg00007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df1789d1");
  script_set_attribute(attribute:"solution", value:
"Install Mac EFI Security Update 2015-002.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/04");

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
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-3CBD00234E554E41",
  make_array(
    "efi-version", "MBP112.88Z.0138.B16.1509081314"
  ),
  "Mac-8ED6AF5B48C039E1",
  make_array(
    "efi-version", "MM51.88Z.0077.B12.1506081728"
  ),
  "Mac-35C1E88140C3E6CF",
  make_array(
    "efi-version", "MBA61.88Z.0099.B20.1509081314",
    "minimum-smc-version", "2.12f135"
  ),
  "Mac-F2268DAE",
  make_array(
    "efi-version", "IM111.88Z.0034.B04.1509231906"
  ),
  "Mac-81E3E92DD6088272",
  make_array(
    "efi-version", "IM144.88Z.0179.B12.1509081439"
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
    "efi-version", "MBA51.88Z.00EF.B04.1509111654"
  ),
  "Mac-031AEE4D24BFF0B1",
  make_array(
    "efi-version", "MM61.88Z.0106.B0A.1509111654"
  ),
  "Mac-7BA5B2794B2CDB12",
  make_array(
    "efi-version", "MM51.88Z.0077.B12.1506081728"
  ),
  "Mac-7DF2A3B5E5D671ED",
  make_array(
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-00BE6ED71E35EB86",
  make_array(
    "efi-version", "IM131.88Z.010A.B09.1509111558"
  ),
  "Mac-F2238AC8",
  make_array(
    "efi-version", "IM112.88Z.0057.B03.1509231647"
  ),
  "Mac-742912EFDBEE19B3",
  make_array(
    "efi-version", "MBA41.88Z.0077.B12.1506081728"
  ),
  "Mac-942B59F58194171B",
  make_array(
    "efi-version", "IM121.88Z.0047.B21.1506101610"
  ),
  "Mac-189A3D4F975D5FFC",
  make_array(
    "efi-version", "MBP111.88Z.0138.B16.1509081438"
  ),
  "Mac-F22586C8",
  make_array(
    "efi-version", "MBP61.88Z.0057.B11.1509232013"
  ),
  "Mac-4B7AC7E43945597E",
  make_array(
    "efi-version", "MBP91.88Z.00D3.B0C.1509111653"
  ),
  "Mac-F22589C8",
  make_array(
    "efi-version", "MBP61.88Z.0057.B11.1509232013"
  ),
  "Mac-C3EC7CD22292981F",
  make_array(
    "efi-version", "MBP101.88Z.00EE.B0A.1509111559"
  ),
  "Mac-7DF21CB3ED6977E5",
  make_array(
    "efi-version", "MBA61.88Z.0099.B20.1509081314",
    "minimum-smc-version", "2.13f7"
  ),
  "Mac-942B5BF58194151B",
  make_array(
    "efi-version", "IM121.88Z.0047.B21.1506101610"
  ),
  "Mac-94245B3640C91C81",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-6F01561E16C75D06",
  make_array(
    "efi-version", "MBP91.88Z.00D3.B0C.1509111653"
  ),
  "Mac-94245A3940C91C80",
  make_array(
    "efi-version", "MBP81.88Z.0047.B2A.1506082203"
  ),
  "Mac-27ADBB7B4CEE8E61",
  make_array(
    "efi-version", "IM142.88Z.0118.B12.1509081435"
  ),
  "Mac-031B6874CF7F642A",
  make_array(
    "efi-version", "IM141.88Z.0118.B12.1509081313"
  ),
  "Mac-F60DEB81FF30ACF6",
  make_array(
    "efi-version", "MP61.88Z.0116.B16.1509081436"
  ),
  "Mac-77EB7D7DAF985301",
  make_array(
    "efi-version", "IM143.88Z.0118.B12.1509081435"
  ),
  "Mac-F2238BAE",
  make_array(
    "efi-version", "IM112.88Z.0057.B03.1509231647"
  ),
  "Mac-F65AE981FFA204ED",
  make_array(
    "efi-version", "MM61.88Z.0106.B0A.1509111654"
  ),
  "Mac-C08A6BB70A942AC2",
  make_array(
    "efi-version", "MBA41.88Z.0077.B12.1506081728"
  ),
  "Mac-66F35F19FE2A0D05",
  make_array(
    "efi-version", "MBA51.88Z.00EF.B04.1509111654"
  ),
  "Mac-2BD1B31983FE1663",
  make_array(
    "efi-version", "MBP112.88Z.0138.B16.1509081314"
  ),
  "Mac-AFD8A9D944EA4843",
  make_array(
    "efi-version", "MBP102.88Z.0106.B0A.1509130955"
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

# Available for: OS X Mavericks v10.9.5
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.9\.5([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.9.5");

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
