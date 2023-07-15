#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124410);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/01 10:40:32");

  script_name(english:"SSL Root Certification Authority Distrusted");
  script_summary(english:"Checks root certification authority's trust status.");

  script_set_attribute(attribute:"synopsis", value:
"A root Certification Authority certificate was found at the top of the
certificate chain that is on a list of distrusted Certification
Authorities.");
  script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate chain that contains a root
Certification Authority certificate at the top of the chain that is
issued from a distrusted Certification Authority.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc778623");
  script_set_attribute(attribute:"solution", value:
"New intermediate certificates and subject certificates must be
created with a trusted root Certification Authority.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_certificate_chain.nasl");
  script_require_keys("SSL/Chain/Distrusted");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

# Get the port that has unused certificates from the KB.
key = "SSL/Chain/Distrusted";
port = get_kb_item_or_exit(key);

# If the user doesn't want the details, let's stop right here.
if (report_verbosity == 0)
{
  security_warning(port);
  exit(0);
}

# Get the self-signed, unrecognized certificate at the top of the
# certificate chain.
attr = get_kb_item_or_exit("SSL/Chain/Root/"+port);

# Report our findings.
report =
  '\nThe following certificate was found at the top of the certificate' +
  '\nchain sent by the remote host, but is found in the list of known' +
  '\ndistrusted certificate authorities :' +
  '\n' +
  '\n' + attr;

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
