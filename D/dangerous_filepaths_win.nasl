#TRUSTED 372d48f3046f5e43f85a767f8b526f375e5b3af82ab2eca7eb3e30c29cbc6205e5dc38f93ac926a439b6221c93fecadbd0711b4265de5a73a87fe7ef2eb994bba7b65db388f62391295adf54cc75e9b9d4cd95d8927e40bb96d1188bca8c37fc0c07747a3ca950f59f68b8074338c67a06989956bec283bdc6c7c776d0eb5a567038d4f91eda9c77281c0497eb4a7c71b74df0a26772e2c874a4b7f907b87f3e68ce5dd94994e49027ce7949188ec7ea7c66415c6ff0262fc3ac9fb2cc1917368382fdb9bc6574fb576283b7b85d05491a45617011b7939d3f8437af59b846ca7a287dcfc6446f65c1ca4647e1b77bde7e601bb3e18d5df6bfbb7b0164e4302da8ace15e686bea15345b5b70c71d72b73373b88d20241fcf7030ee21fc9e53138a1faa0d13df4cf411ea8452fcebfa696d1b6255565508d95b5443189d43a5e9155010ca1a04f7a5b499b41714bc95ce97889b9520fcfaed6196d7a756a8a8006d3028cac49b6d1ab97078fe1cd9ea558d5c46432db4d4ec189b6e2ae12fdfbff52ba9ea1cf58b9bae09e09631f0ce45d882e9824758456bf6b799a88c2d166d1371bc973b7dd1982550e07f8e6663cb54c83209a17793f781e9f78a8d3e3e98e801d7fd098de22b1619bf9e371d69426a0cede00c2e2984a30da5033fd40a5efde6756c485d742f943cb030a7a89f885d19fd6badc392a27b0920623012d165
#TRUST-RSA-SHA256 97f9dec3daeb45f1598a55814a45fb8dde532ad803a8ebd2bfbee46853539334292923ce82b0555087ae3254e9bee15db1d32d5d4e3f0fb1b55dd4e282b8b1226ec7cc816924c912ec264041ae75018404e80623850a2b271f5a29677b8a3568637ec391e3c88cdd23fc993ef318b1ae4d3907a250ca197bf9100723adcb556ec1d2e2067cd31200a66e3b773579e0644db01bc7f3d377fc340c6a2ce92c216cac7fee613a24778b2091e60ff786930e1222abd8feccfb9ee85e29b5767877f74abe92dca84ca0dcb971a8a519405f51f97e7bf075b96ba8f5e9d915ac33bd4b451bdabac64ec82adfffc7a6d85404c9a7ae356150bd0a239ec8dbd86fdc9285250e1bce0f210e0495869c05af7116d2e71243f623964473d736a604efb2f656bcdc59c3466e43b3ffff0d672d38209986e6aefd70deb014326f263a8348721c0bab42b811fca14c576b341e80f5c091bc1739c88f4e388c02919dfd95d3aa1d50ceea45d4e776506c17c9073221bd2125bade50a1ad615d779f1844a0ae395720f617029aec429f04d61f9384712942c50acd8327e1fc3f0890a0c6496e50d6b8c4d4ed6fc8ecf43ad8e6b865519b262c2c34573cf621f7da7a27e6100b5d6bb2fb7726449b84ea17d29ab321a350a6b6ef5618e19554b9bd9fa9c3d3a75a4de262e77eceec364c434d362008e658c393aadc099954b77beca623190754c052
#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(168981);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/21");

  script_name(english:"Filepaths contain Dangerous characters (Windows)");
  script_summary(english:"Reports filepaths with dangerous characters.");

  script_set_attribute(attribute:"synopsis", value:
"This Tenable product detected files or paths on the scanned Windows system which contain characters with command
injection or privilege escalation potential.");
  script_set_attribute(attribute:"description", value:
"This Tenable product detected files or paths on the scanned Windows system which contain characters with command
injection or privilege escalation potential. Although characters such as singlequote, ampersand, and semicolon are
perfectly valid Windows filepath characters, use of them may lead to problems or security compromise when used in
further commands.

This product has chosen in certain plugins to avoid digging within those files and directories for security reasons.
These should be renamed to avoid security compromise.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"solution", value:"Rename these files or folders to not include dangerous characters.");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys('Host/Windows/dangerous_filepaths_found');
  exit(0);
}

include("smb_func.inc");
include('win_paths.inc');

# We call this in case we rewrote it for testing purposes
local_detection_win::append_path();

get_kb_item_or_exit('Host/Windows/dangerous_filepaths_found');

var res = query_scratchpad("SELECT DISTINCT path FROM windows_dangerous_filepaths ORDER BY path ASC");

if (empty_or_null(res))
{
  exit(0, "No dangerous windows filespaths were found.");
}

var report =
  'The following files and directories contain characters such as singlequote, ampersand, or semicolon. This scanner\n' +
  'avoided access to these files when possible for safety:\n';

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
security_report_v4(port:kb_smb_transport_no_branch(), extra:report, severity:SECURITY_NOTE);
