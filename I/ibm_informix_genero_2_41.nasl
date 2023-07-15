#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(64379);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2011-3026");
  script_bugtraq_id(52049);

  script_name(english:"IBM Informix Genero < 2.41 png_decompress_chunk Integer Overflow");
  script_summary(english:"Checks version of IBM Informix Genero");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is potentially affected by
an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of IBM Informix Genero is earlier than 2.41 and
is, therefore, potentially affected by an integer overflow vulnerability
in the libpng library used by this application.  When decompressing
certain PNG image files, this could be exploited to crash the
application or even execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21620982");
  # https://www.ibm.com/blogs/psirt/security-bulletin-ibm-informix-genero-vulnerable-to-libpng-chunk-decompression-integer-overflow-vulnerability-cve-2011-3026/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0c30d9c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Genero 2.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:informix_genero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_informix_genero_installed.nasl");
  script_require_keys("SMB/IBM_Informix_Genero/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = 'IBM Informix Genero';
kb_base = "SMB/IBM_Informix_Genero/";
report = '';
fix = "2.41";

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');
port = get_kb_item('SMB/transport');
if (!port) port = 445;

for (install_num =0; install_num < num_installed; install_num++) 
{
  ver = get_kb_item_or_exit(kb_base+install_num+"/Version", exit_code:1);
  path = get_kb_item_or_exit(kb_base+install_num+"/Path");

  if (ver =~"2\." && ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
  {
    report += 
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
  }
}
if (report !='')
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);
