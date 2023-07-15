#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17770);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2007-5536");
  script_bugtraq_id(26093);

  script_name(english:"OpenSSL < vA.00.09.07l on HP-UX Local Denial of Service");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than vA.00.09.07l on HP-UX.  As such, it is is
affected by an unspecified local denial of service vulnerability.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c01203958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?432e1580");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL vA.00.09.07l or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl", "os_fingerprint.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("HP-UX" >!< os) exit(0, "The remote host is not HP-UX.");
}

openssl_check_version(fixed:'0.9.7m', severity:SECURITY_WARNING);
