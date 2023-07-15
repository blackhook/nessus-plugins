#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47595);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-2645",
    "CVE-2010-2646",
    "CVE-2010-2647",
    "CVE-2010-2648",
    "CVE-2010-2649",
    "CVE-2010-2650",
    "CVE-2010-2651",
    "CVE-2010-2652"
  );
  script_bugtraq_id(41334, 44215, 44217);
  script_xref(name:"SECUNIA", value:"40479");

  script_name(english:"Google Chrome < 5.0.375.99 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 5.0.375.99.  It therefore is reportedly affected by multiple
vulnerabilities :

  -  An unspecified error allows an out-of-bounds read with
     WebGL. (Issue #42396)

  -  An unspecified error exists in the process of isolating
     sandboxed iframes. (Issue #42575, #42980)

  -  An unspecified memory corruption error exists in the
     handling invalid SVG images. (Issue #43488)

  -  An unspecified memory corruption error exists in the
     implementation of a  bidirectional algorithm.
     (Issue #44424)

  -  An unspecified error in the processing of certain
     invalid images can lead to application crashes.
     (Issue #45164)

  -  An unspecified memory corruption error exists in the
     processing of PNG images and can lead to application
     crashes. (Issue #45983)

  -  An unspecified memory corruption error exists in the
     processing of CSS. (Issue #46360)

  -  An unspecified error exists in the handling of print
     dialogs. (Issue #46575)

  -  An unspecified error exists in the handling of modal
     dialogs and can lead to application crashes.
     (Issue #47056)");
  # https://chromereleases.googleblog.com/2010/07/stable-channel-update.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59a99aa2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome 5.0.375.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}


include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'5.0.375.99', severity:SECURITY_HOLE);
