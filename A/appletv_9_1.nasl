#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94050);
  script_version("1.8");
  script_cvs_date("Date: 2019/02/26  4:50:08");

  script_cve_id(
    "CVE-2011-2895",
    "CVE-2015-7038",
    "CVE-2015-7039",
    "CVE-2015-7040",
    "CVE-2015-7041",
    "CVE-2015-7042",
    "CVE-2015-7043",
    "CVE-2015-7047",
    "CVE-2015-7048",
    "CVE-2015-7051",
    "CVE-2015-7053",
    "CVE-2015-7054",
    "CVE-2015-7055",
    "CVE-2015-7058",
    "CVE-2015-7059",
    "CVE-2015-7060",
    "CVE-2015-7061",
    "CVE-2015-7064",
    "CVE-2015-7065",
    "CVE-2015-7066",
    "CVE-2015-7068",
    "CVE-2015-7072",
    "CVE-2015-7073",
    "CVE-2015-7074",
    "CVE-2015-7075",
    "CVE-2015-7079",
    "CVE-2015-7083",
    "CVE-2015-7084",
    "CVE-2015-7095",
    "CVE-2015-7096",
    "CVE-2015-7097",
    "CVE-2015-7098",
    "CVE-2015-7099",
    "CVE-2015-7100",
    "CVE-2015-7101",
    "CVE-2015-7102",
    "CVE-2015-7103",
    "CVE-2015-7104",
    "CVE-2015-7105",
    "CVE-2015-7109",
    "CVE-2015-7110",
    "CVE-2015-7111",
    "CVE-2015-7112",
    "CVE-2015-7115",
    "CVE-2015-7116"
  );
  script_bugtraq_id(
    49124,
    78719,
    78720,
    78725,
    78726,
    78728,
    78728,
    78732,
    78733,
    78735,
    80379
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-12-08-2");
  script_xref(name:"EDB-ID", value:"39357");
  script_xref(name:"EDB-ID", value:"38917");

  script_name(english:"Apple TV < 9.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Apple TV device is
prior to 9.1. It is, therefore, affected by multiple vulnerabilities
in the following components :

  - AppleMobileFileIntegrity
  - Compression
  - CoreGraphics
  - CoreMedia Playback
  - Disk Images
  - dyld
  - ImageIO
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit SCSI
  - Kernel
  - libarchive
  - libc
  - libxml2
  - MobileStorageMounter
  - OpenGL
  - Security
  - WebKit

Note that only 4th generation models are affected by the
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205640");
  # https://lists.apple.com/archives/security-announce/2015/Dec/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?951f278f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 9.1 or later. Note that this update is
available only for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7116");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("appletv_func.inc");
include("audit.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

# fix
fixed_build = "13T402";
tvos_ver = "9.1"; # for reporting purposes only

# determine gen from the model
gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build        : build,
  fix          : fixed_build,
  affected_gen : 4,
  fix_tvos_ver : tvos_ver,
  model        : model,
  gen          : gen,
  severity     : SECURITY_HOLE,
  port         : port,
  url          : url
);
