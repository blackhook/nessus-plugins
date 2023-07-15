##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(501226);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/03");

  script_name(english:"Rockwell Automation ControlLogix® Communications Modules Resiliency Update");

  script_set_attribute(attribute:"synopsis", value:
"The Rockwell Automation ControlLogix® Communications Modules have received a resiliency update.");
  script_set_attribute(attribute:"description", value:
"A version bump was observed for Rockwell Automation ControlLogix® Communications
Modules. Rockwell says that product improvements have been made to
increase product resiliency to potentially disruptive activities. In the
interest of security best practices, it is recommended to update to the latest
version immediately.

Note: Plugin will be updated as more information from the vendor becomes available

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  
  # https://compatibility.rockwellautomation.com/Pages/MultiProductSelector.aspx?crumb=111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a39743bf");
  script_set_attribute(attribute:"solution", value:
  "Update to 11.004 or later or see Rockwell Automation's suggested actions and best practices");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_d_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tp_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2f_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2f_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_d_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4tr_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4tr_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4tr_series_d_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Rockwell");

  exit(0);
}


include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Rockwell');

var asset = tenable_ot::assets::get(vendor:'Rockwell');

var vuln_cpes = {
    "cpe:/o:rockwellautomation:1756-en2t_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_c_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_c_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_d_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tp_series_a_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_a_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_b_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_d_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4tr_series_a_firmware:-" :
        {"versionEndIncluding" : "5.002", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4tr_series_b_firmware:-" :
        {"versionEndIncluding" : "5.002", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4tr_series_c_firmware:-" :
        {"versionEndIncluding" : "5.002", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4tr_series_d_firmware:-" :
        {"versionEndIncluding" : "5.002", "family" : "ControlLogix"}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
