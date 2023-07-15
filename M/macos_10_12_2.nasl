#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95917);
  script_version("1.9");
  script_cvs_date("Date: 2020/01/07");

  script_cve_id(
    "CVE-2016-1777",
    "CVE-2016-1823",
    "CVE-2016-4688",
    "CVE-2016-4691",
    "CVE-2016-4693",
    "CVE-2016-5419",
    "CVE-2016-5420",
    "CVE-2016-5421",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-7141",
    "CVE-2016-7167",
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418",
    "CVE-2016-7588",
    "CVE-2016-7591",
    "CVE-2016-7594",
    "CVE-2016-7595",
    "CVE-2016-7596",
    "CVE-2016-7600",
    "CVE-2016-7602",
    "CVE-2016-7603",
    "CVE-2016-7604",
    "CVE-2016-7605",
    "CVE-2016-7606",
    "CVE-2016-7607",
    "CVE-2016-7608",
    "CVE-2016-7609",
    "CVE-2016-7612",
    "CVE-2016-7615",
    "CVE-2016-7616",
    "CVE-2016-7617",
    "CVE-2016-7618",
    "CVE-2016-7619",
    "CVE-2016-7620",
    "CVE-2016-7621",
    "CVE-2016-7622",
    "CVE-2016-7624",
    "CVE-2016-7625",
    "CVE-2016-7627",
    "CVE-2016-7628",
    "CVE-2016-7629",
    "CVE-2016-7633",
    "CVE-2016-7636",
    "CVE-2016-7637",
    "CVE-2016-7643",
    "CVE-2016-7644",
    "CVE-2016-7655",
    "CVE-2016-7657",
    "CVE-2016-7658",
    "CVE-2016-7659",
    "CVE-2016-7660",
    "CVE-2016-7661",
    "CVE-2016-7662",
    "CVE-2016-7663",
    "CVE-2016-7714",
    "CVE-2016-7742",
    "CVE-2016-7761",
    "CVE-2016-8615",
    "CVE-2016-8616",
    "CVE-2016-8617",
    "CVE-2016-8618",
    "CVE-2016-8619",
    "CVE-2016-8620",
    "CVE-2016-8621",
    "CVE-2016-8622",
    "CVE-2016-8623",
    "CVE-2016-8624",
    "CVE-2016-8625"
  );
  script_bugtraq_id(
    85054,
    90698,
    92292,
    92306,
    92309,
    92754,
    92975,
    92984,
    93004,
    93005,
    93006,
    93007,
    93008,
    93009,
    93011,
    93150,
    94094,
    94096,
    94097,
    94098,
    94100,
    94101,
    94102,
    94103,
    94105,
    94106,
    94107,
    94572,
    94903,
    94904,
    94905,
    94906
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-12-13-1");

  script_name(english:"macOS 10.12.x < 10.12.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that is 10.12.x prior to
10.12.2. It is, therefore, affected by multiple vulnerabilities in the
following components :

  - apache_mod_php
  - AppleGraphicsPowerManagement
  - Assets
  - Audio
  - Bluetooth
  - CoreCapture
  - CoreFoundation
  - CoreGraphics
  - CoreMedia External Displays
  - CoreMedia Playback
  - CoreStorage
  - CoreText
  - curl
  - Directory Services
  - Disk Images
  - FontParser
  - Foundation
  - Grapher
  - ICU
  - ImageIO
  - Intel Graphics Driver
  - IOFireWireFamily
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit
  - IOSurface
  - Kernel
  - kext tools
  - libarchive
  - LibreSSL
  - OpenLDAP
  - OpenPAM
  - OpenSSL
  - Power Management
  - Security
  - syslog
  - WiFi
  - xar

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.

Furthermore, CVE-2016-6304, CVE-2016-7596, and CVE-2016-7604 also
affect Mac OS X versions 10.10.5 and 10.11.6. However, this plugin
does not check those versions.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207423");
  # http://lists.apple.com/archives/security-announce/2016/Dec/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dabd46");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7644");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("vcf.inc");
include("vcf_extras_apple.inc");

app_info = vcf::apple::get_macos_info();

vcf::apple::check_macos_restrictions(restrictions:['10.12']);

constraints = [{ "fixed_version" : "10.12.2" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
