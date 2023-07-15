#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177342);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-29402", "CVE-2023-29404", "CVE-2023-29405");
  script_xref(name:"IAVB", value:"2023-B-0040");

  script_name(english:"Golang < 1.19.10 / 1.20.x < 1.20.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang Go installed on the remote host is affected by multiple vulnerabilities:

  - The go command may generate unexpected code at build time when using cgo. This may result in unexpected behavior 
    when running a go program which uses cgo. This may occur when running an untrusted module which contains 
    directories with newline characters in their names. Modules which are retrieved using the go command, i.e. via 'go
    get', are not affected (modules retrieved using GOPATH-mode, i.e. GO111MODULE=off, may be affected). 
    (CVE-2023-29402)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running 'go get' on a 
    malicious module, or when running any other command which builds untrusted code. This is can by triggered by linker
    flags, specified via a '#cgo LDFLAGS' directive. The arguments for a number of flags which are non-optional are 
    incorrectly considered optional, allowing disallowed flags to be smuggled through the LDFLAGS sanitization. This 
    affects usage of both the gc and gccgo compilers. (CVE-2023-29404)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running 'go get' on a 
    malicious module, or when running any other command which builds untrusted code. This is can by triggered by linker 
    flags, specified via a '#cgo LDFLAGS' directive. Flags containing embedded spaces are mishandled, allowing 
    disallowed flags to be smuggled through the LDFLAGS sanitization by including them in the argument of another flag. 
    This only affects usage of the gccgo compiler. (CVE-2023-29405)
 
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/60167");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/60305");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/60306");
  # https://groups.google.com/g/golang-announce/c/q5135a9d924/m/j0ZoAJOHAwAJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e05d2017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.19.10, 1.20.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29405");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.19.10' },
  { 'min_version' : '1.20', 'fixed_version' : '1.20.5' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);