#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165303);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2022-2085");
  script_xref(name:"IAVB", value:"2022-B-0034-S");

  script_name(english:"Artifex Ghostscript 9.55 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows host is 9.55. It is, therefore, affected 
by a NULL pointer dereference vulnerabiulity leading to denial of service. The DoS occurs when Ghostscript tries to 
render a large number of bits in memory. When allocating a buffer device, it relies on an init_device_procs defined 
for the device that uses it as a prototype that depends upon the number of bits per pixel. For bpp > 64, mem_x_device 
is used and does not have an init_device_procs defined. This flaw allows an attacker to parse a large number of bits 
(more than 64 bits per pixel), which triggers a NULL pointer dereference flaw, causing an application to crash.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.ghostscript.com/show_bug.cgi?id=704945");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifex Ghostscript  9.56.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2085");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include('vcf.inc');

var app = 'Ghostscript';

var constraints = [{'min_version' : '9.55.0', 'fixed_version' : '9.56.0'}];

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

