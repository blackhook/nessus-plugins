#TRUSTED 6a85814aaae57eddd954cde968ae993e417ab93a5cfbb6fde825a83f48b872adae977a032746f734b23bce9633c6002dfec0e483bcba8933e1256ad8702198c9ae77e7da3ef8c07292f0e5a4b08ce3c8c2a34ac06e05e0cc628f89adf2173168928d106c22ccbaaeb80358480029f35c04e6aefc41233f965bdd908b6148b3b387182450b01e55e8e12c092fef78d7c3db4db11519e8e7288966e0a1f97537b377c6767a21c6858053a8fed6c52ddadaf6c092072ada7aace6c87220dd23e452278120689185919b675c8e5697c336510375bd59f683c4dcfe52aff86ca122d88ac414a7df926053da36822e76216b57c6d28a53413bcfd6b345b6d0df807dc78b9484e93a70d2b2a89664fde751016228dfdbe4c972be124f2f776cbc39bff660675c8adc63188cf929e4a1dcd0b60296beeff3bbb9a073eb55d0f750dab8497e2a7419847a42cac81aef8da8bb6cc15e1216ee1d74e099ba3e4a343415cb4f240fface7b3366f934df9efd1ff3d969069969b9029023a123efe2cde72ac51ddad50371bfa1c5b0423d3c1c31be2ccdd91ca16f78ca4edc5c764b0fa110801bab2e6cf95e05ad7677431f2e7e96cc23147b6f48b6758d6bc8810b84d9d163573097e737a7df2324720c9d06be630204837ba108bdbf9018af21d1b93bb3a3ffe9c246d6bc83960012cfb7c05fdb0827447a3ed850d3c6bb87739c0a0a89b66c
#TRUST-RSA-SHA256 3e386123360dffc3cc2ff7f3bbe9ba95a8429088bf3e12330205e0f527769056a1ca4f421c1bdb5fc895b1a421f210a5f03a9815e83664e6239976a34a42ed313d59902ff60b76a627a638423ce089b5f49f8e11df11f22a81ce02848f5103f86f6b711c8ffd58fd4be70b5f62b2ce86b6e0ba20a2da853587b6370b257f95726b8bff0021e23955193e3f5440447389b6be780a627678f6fb76307694a0783ccfb4750a08092d08002c31c51f1bcb44d2b9a29d11a4cbc79c2087eca0d30186213a88d10434dd7493a3f7cf8afef6d0ad924ac02de8afa3263a2fc03fad64e5eb799c86432b19e3b46059fdfb93e670bf15f3655d6d15a349150617dd5b228523fe32898611f004bb5cffb91a06220aff70c71dd407c43b52c3c9e4b03bf3849b21850d5b1a51920305c6c555236e241d7fb4fab4c05c3ecbda625b9bbe102694ced0827203fb66c2d6960c01a4b0bdfd5d4f62f7533421ea5a1894d560c8e846226483d59e91509ce3fbfcf1fb5c8abd5233d57c1ed28df487094eccc7c03a826c923ae90095a34a00f6abfdb6517ff55e6babc07131319477366f6e2833bff96e6d018e3b5e3a9fc4dbc570a99992e86542c0b2001a7c05250803d16eb8e41d9f9a679258d332ecc29d35e5552b520f1c833421e0acf61ed1474f938b241ea7e655dd630153e649288c2e4e9e062a0e35e57837f4690fde19b931b0051da2
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(168982);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"Filepaths contain Dangerous characters (Linux)");
  script_summary(english:"Reports filepaths with dangerous characters.");

  script_set_attribute(attribute:"synopsis", value:
"This Tenable product detected files or paths on the scanned Unix-like system which contain characters with command
injection or privilege escalation potential.");
  script_set_attribute(attribute:"description", value:
"This Tenable product detected files or paths on the scanned Unix-like system which contain characters with command
injection or privilege escalation potential. Although almost any character is valid for an entry in this kind of
filesystem, such as semicolons, use of some of them may lead to problems or security compromise when used in further
commands.

This product has chosen in certain plugins to avoid digging within those files and directories for security reasons.
These should be renamed to avoid security compromise.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"solution", value:"Rename these files or folders to not include dangerous characters.");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys('Host/Linux/dangerous_filepaths_found');
  exit(0);
}

include("ssh_func.inc");
include("lcx.inc");

# We call this in case we rewrote it for testing purposes
lcx::check_localhost();

get_kb_item_or_exit('Host/Linux/dangerous_filepaths_found');

var res = query_scratchpad("SELECT DISTINCT path FROM nix_dangerous_filepaths ORDER BY path ASC");

if (empty_or_null(res))
{
  exit(0, "No dangerous linux filespaths were found.");
}

var report =
  'The following files and directories contain potentially dangerous characters such as brackets, ampersand, or semicolon.\n' +
  'This scanner avoided access to these files when possible for safety:\n';

var headerlength = strlen(report);

foreach var entry (res)
{
  entry = entry['path'];
  report += '\n' + entry;
}

if (strlen(report) == headerlength)
{
  # This should never happen, something really went wrong if the entries didn't write to the array correctly
  # Check anyway, reporting by default without this check would be unacceptable.
  exit(1, "Error reading dangerous windows filepath entries.");
}
security_report_v4(port:kb_ssh_transport(), extra:report, severity:SECURITY_NOTE);
