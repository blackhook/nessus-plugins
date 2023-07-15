#TRUSTED 568d588c6cc260f89fc1c904566ce4e3b527ed286f5a21dff23b1cc86740febca52d3a01211db199e06122b28701d06d48f3ed929f4ab3cb9d229e797d2ea618f4cef5dc984cb1f23a10d32ec78fc6990e7a93116ad560f92d9adab873feea780bf3c19d6952529e4cf06aed2ac571119e413cf97a9b001c98adcc4533dc80151365d0e2f4a9602db2b0c0cb96f6c52e16cd46182ebd59c47346e2d29f286518b5b4890d1d5ea09de04edcfcd1ea6ed9ae73fa2121be0d3f54bb24fa0f8b33314d1e7f6473623c7e742716bc94c5fc127e56a1f4617cac804d9e09e61133fc566db51fa23d88ed24dbb40329a867a6aad062297ee61d664ebbb7240b743502d14adc116367524dde5a69ce89f74d44c913c9c64982727b0b1e99c8ee1d258fb3f40ffaed65f4ae367ea10f7b336ee30a0fc5cfba35250b8b7b64ed166a73843714783316f6e3a236536a2269ec7a90120cd24bc1140032e02e74d7355fabd5424ccb60f071f2be09a603e15ccd66d631b40a2267eb05c3a46e5019fde1aca6aa69c4936e57313955fa392daea5b090a3a14df46c585088469b78a01983fef6e9f84f42a15f1b679f999f11deda49e79ed4ce69878472079dcb14e2949c4c78b2c5f669707fb7b728c202db7feb352657e5c3ec5b4be6acd8c25f6c531a279b4d9ddee23513963958f4c3f4c88585fd79307c164a8936b0b5f607b751670ed4ff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69912);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/11/22");

  script_name(english:"Cisco Application Control Engine (ACE) Version");
  script_summary(english:"Obtains the ACE version.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the version of the Cisco Application Control
Engine (ACE) software installed on the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"Cisco Application Control Engine (ACE) software is installed on the
remote Cisco IOS or ACE device. It is a load-balancing and
application-delivery solution for Cisco Catalyst 6500 Series switches
and Cisco 7600 Series routers, and it is also available as an
appliance.");
  # https://www.cisco.com/c/en/us/products/interfaces-modules/ace-application-control-engine-module/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a80d18e9");
  # https://www.cisco.com/c/en/us/products/application-networking-services/product-listing.html#DataCenterApplicationServices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d97a1e0e");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_ports("Host/Cisco/ACE/Version", "Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = NULL;

# nb: ssh_get_info.nasl can get version info with newer releases of ACE
#     by running "show version"; for other releases, we'll try to run
#     some additional commands.
version = get_kb_item("Host/Cisco/ACE/Version");
if (isnull(version))
{
  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
  if (!get_kb_item("Host/Cisco/IOS/Version")) audit(AUDIT_OS_NOT, "Cisco IOS");

  failed_cmds = make_list();
  is_ace = FALSE;
  override = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (!check_cisco_result(buf)) failed_cmds = make_list(failed_cmds, "show module");
  else if ("Application Control Engine Module" >< buf)
  {
    is_ace = TRUE;

    match = eregmatch(pattern:"\)ACE (A[0-9]+\([^\)]+\))", string:buf);
    if (!isnull(match)) version = match[1];
  }

  if (isnull(version))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (!check_cisco_result(buf))
    {
      failed_cmds = make_list(failed_cmds, "show inventory");
      if (cisco_needs_enable(buf)) override = 1;
    }
    else if ('DESCR: "Application Control Engine Service Module"' >< buf)
    {
      is_ace = TRUE;

      match = eregmatch(pattern:"system:[ \t]+Version[ \t]+(A[0-9].+)[ \t]+\[build ", string:strstr(buf, "Software:"));
      if (!isnull(match)) version = match[1];
    }
  }

  if (max_index(failed_cmds) == 2) exit(1, "Failed to determine if Cisco ACE is installed.");
  if (!is_ace) audit(AUDIT_NOT_INST, "Cisco ACE");
  if (!version) exit(1, "Failed to extract the Cisco ACE version.");

  set_kb_item(name:"Host/Cisco/ACE/Version", value:version);
}
# Parse model from appliance
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
  if (check_cisco_result(buf))
  {
    # Appliance
    pattern = 'DESCR: "ACE ([0-9]+) Application Control Engine Appliance"';
    match = eregmatch(pattern:pattern, string:buf);
    if (!isnull(match))
    {
      model = match[1];
      set_kb_item(name:"Host/Cisco/ACE/Model", value:model);
    }

    if (isnull(model))
    {
      # Module
      pattern = " PID: (ACE[0-9]+)-";
      match = eregmatch(pattern:pattern, string:buf);
      if (!isnull(match))
      {
        model = match[1];
        set_kb_item(name:"Host/Cisco/ACE/Model", value:model);
      }
    }
  }
}

if (report_verbosity > 0)
{
  report = NULL;
  if (!isnull(model)) report = '\n  Model   : ' + model;
  report += '\n  Version : ' + version +
            '\n';
  security_note(port:0, extra:report + cisco_caveat(override));
}
else security_note(port:0, extra:cisco_caveat(override));
