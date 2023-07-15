#TRUSTED 697dedeb9c317bd999ecc2c2345137cee21b78ee42ae8221577bf1825b4f4c7e80bbaf44f26f257a4b5a6788b0ae2e7bef6531b21d941a2edc5cbf292f0a3dea69cca3902b1698d1a0ded1e4a602340f7cc6d70d924080798786ebd0607ded3eade86444b7273bd0f51f5b0cb30cdcca78e366ddba801162dbc9e52f6b661070b328dff5eb0739b294d3b2a4bb091249d7d363310238a1c98705bc18bd54f393333baa2e6cf44d61956a5366d9716af66d0371df433ed9b771a45cd910d869aeb9f2b44fbe8149a5f735e7a870f530e3bb8ca2758461f7d16d6f20536ccd501e48336f6a6431ecf7895628f011eb5f4091f14358265815b70475e64668364ca098f9e08b4276ae63855b87f8f0f53815f3128716edd73f87373409e5b7776c180563948347d2153edd98b72de6cadf428f24afb25690879bbdc87af04fdee24bff934e4019b13319708112228a7b6757f5a0dcf5b8e02e3833d8ebaa861f96a58736e2ea0460e6994d035e81dd060bdf074d7f92b303c55801abc25e52d93b1f45b5fc29755f8cdce0d3ba08077519fad252a607f904c10e415a9d9e8c05dd45144aba5ca14181bbd5bb6eacc89aa1502ef5576a94b8afa3b16ed03b24a3292fdaab13ca506f65ae856c55d0ae9e1b04b8884bd472a8be5ddc0bb58d790a1795bd5d1c9f476651d7ed590086aebebb1a05e94260e69a4fbc2d5197fef47d50c6
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(156594);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/11");

  script_name(english:"Parse CAs from UI Input");

  script_summary(english:
    "This plugin checks for data in from the Trusted CAs UI input, and stores the info (if any) in the KB");

  script_set_attribute(attribute:"description", value:
    "This plugin checks for data in from the Trusted CAs UI input, and stores the info (if any) in the KB");
  script_set_attribute(attribute:"synopsis", value:"This plugin stores Trusted CAs input into the KB");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_type", value:"settings");
  script_end_attributes();

  script_category(ACT_INIT);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Settings");

  exit(0);
}

# Wrapper for get_preferences to make Flatline testing easier.
function get_input(input)
{
  if (get_kb_item("TEST/is_test"))
    return get_kb_item("TEST/"+input);
  else
    return get_preference(input);
}

var input_from_ui = get_input(input:"trusted_cas");

if (!empty_or_null(input_from_ui))
  replace_kb_item(name:"SSL/CA_input", value:input_from_ui);

exit(0);
