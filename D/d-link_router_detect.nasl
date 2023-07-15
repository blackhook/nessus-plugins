#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44319);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"D-Link Router Detection");
  script_summary(english:"Detects D-Link Routers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is a D-Link router."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote device is a D-Link router.  These devices route packets and
may provide port forwarding, DMZ configuration and other networking
services."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dlink.com/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Disable this hardware if it violates your corporate policy."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:di-604_broadband_router");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dap-1533");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-862l");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-835");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:d-link:dir-855l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dhp-1565");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-866l");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-825");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dlink:dir-655");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:dir-652");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dlink:dir-615");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 8099, 8181);

  exit(0);
}

include("http.inc");
include("webapp_func.inc");

var app = 'D-Link Routers';
var cpe = 'x-cpe:/h:d-link';
var extra = make_array();
var detected = FALSE;

var firmware = UNKNOWN_VER;
var modelname, modeldesc;
modelname = NULL;
modeldesc = NULL;

var ports = add_port_in_list(list:get_kb_list("Services/www"), port:8099);
foreach var port (ports)
{
  if (get_port_state(port))
  {
    detected = FALSE;
    
    var res = http_get_cache(item:"/", port:port, exit_on_fail: 0); 

    ##
    # The value within the HTML <title> tag will vary slightly depending
    # on the device model. 
    # 
    # Note: The server header in the response is not always the same.
    # Results have shown httpd or lighttpd depending on the model.
    #
    # Models confirmed to use 'D-LINK CORPORATION, INC' in <title>
    #   * DIR-655
    #   * DIR-657
    #   * DIR-825
    #   
    # Models confirmed to use 'D-LINK SYSTEMS, INC' in <title>
    #   * DIR-862L
    #
    # Most honeypots that emulate the D-LINK DIR-NNN routers are not likely
    # to support the '<H4>404 Not Found</H4>' or '<h1>404 - Not Found</h1>'
    # in the response. 
    # 
    # This message can be used as part of the detection check to ensure a 
    # real device exists as emulated devices are not likely to handle the 
    # 404 message in the same way.
    ##

    var res_404 = http_send_recv3(
      method        : 'GET',
      item          : '/test.js',
      port          : port,
      fetch404      : TRUE,
      exit_on_fail  : FALSE
    );

    if (!isnull(res))
    {
      if (service_is_unknown(port:port)) register_service(port:port, proto:"www");

      if ("<VendorName>D-Link Systems</VendorName>" >< res)
      {
        if ("<ModelName>" >< res && "</ModelName>" >< res)
        {
          modelname = strstr(res, "<ModelName>") - "<ModelName>";
          modelname = modelname - strstr(modelname, "</ModelName>");
          extra['Model'] = modelname;
          replace_kb_item(name:"d-link/model", value:modelname);
        }

        if ("<ModelDescription>" >< res && "</ModelDescription>" >< res)
        {
          modeldesc = strstr(res, "<ModelDescription>") - "<ModelDescription>";
          modeldesc = modeldesc - strstr(modeldesc, "</ModelDescription>");
          extra['Description'] = modeldesc;
        }

        if ("<FirmwareVersion>" >< res && "</FirmwareVersion>" >< res)
        {
          firmware = strstr(res, "<FirmwareVersion>") - "<FirmwareVersion>";
          firmware = firmware - strstr(firmware, "</FirmwareVersion>");
          extra['Firmware'] = firmware;
          replace_kb_item(name:"d-link/firmware", value:firmware);
        }

        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

        dlink = TRUE;
			}
      else if (
        ('D-LINK SYSTEMS, INC.'     >< res && '<H4>404 Not Found</H4>'    >< res_404[2]) ||  # httpd
        ('D-LINK CORPORATION, INC'  >< res && '<H4>404 Not Found</H4>'    >< res_404[2]) ||  # httpd
        ('D-LINK SYSTEMS, INC.'     >< res && '<h3>404 - Not Found</h3>'  >< res_404[2]) ||  # lighthttpd
        ('D-LINK CORPORATION, INC'  >< res && '<h3>404 - Not Found</h3>'  >< res_404[2])     # lighthttpd
        )
      { 
        var current_prod_match = pregmatch(string:res, pattern:'<a href=".*support.dlink.com.*">(DIR-\\w+)');
        if (!isnull(current_prod_match)) modelname = current_prod_match[1];
        
        if ('>Product Page :' >< res)
        {
          if ('<div class="pp">Product Page :' >< res)
          {
            modelname = strstr(res, '<div class="pp">Product Page :') - '<div class="pp">Product Page : ';
            modelname = modelname - strstr(modelname, '<a href');
          }
          else if ('<span class="product">Product Page :' >< res)
          {
            modelname = strstr(res, '<span class="product">Product Page :') - '<span class="product">Product Page : ';
            modelname = strstr(modelname, '>') - '>';
            modelname = modelname - strstr(modelname, '</a>');
          }
        }
        if (modelname)
        {
          extra['Model'] = modelname;
          replace_kb_item(name:"d-link/model", value:modelname);
        }
      
        # RegEx patterns handle different firmware version based on changes to web interface
        var latest_fwver_match = pregmatch(string:res, pattern:'<td align="right"\\snowrap><script>show_words\\(sd_FWV\\)</script>:\\s([\\w.]+)');
        if (!isnull(latest_fwver_match)) firmware = latest_fwver_match[1];
        
        var legacy_fwver_match = pregmatch(string:res, pattern:'class="fwv".*> *: *([\\w.]+) *<span id="fw_ver"');
        if (!isnull(legacy_fwver_match)) firmware = legacy_fwver_match[1];

        if ('>Firmware Version' >< res)
        {
          if ('<div class="fwv">Firmware Version :' >< res)
          {
            firmware = strstr(res, '<div class="fwv">Firmware Version :') - '<div class="fwv">Firmware Version : ';
            firmware = firmware - strstr(firmware, '<span id="fw_ver"');
          }
          else if ('<span class="version">Firmware Version :' ><  res)
          {
            firmware = strstr(res, '<span class="version">Firmware Version :') - '<span class="version">Firmware Version : ';
            firmware = firmware - strstr(firmware, '</span>');
          }

          if (firmware)
          {
            extra['Firmware'] = firmware;
            replace_kb_item(name:"d-link/firmware", value:firmware);
          }
        }

        replace_kb_item(name:"www/d-link", value:TRUE);
        replace_kb_item(name:"www/"+port+"/d-link", value:TRUE);
        replace_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

        detected = TRUE;
      }
    }
    if (detected)
    {
      register_install(
        vendor    : "D-Link",
        product   : "D-Link Routers",
        app_name  : app,
        path      : '/',
        port      : port,
        version   : firmware,
        webapp    : TRUE,
        extra     : extra,
        cpe       : cpe
      );
      
      report_installs(app_name:app, port:port);
    }
  }
}

if (!detected) audit(AUDIT_WEB_APP_NOT_INST, app, port);
