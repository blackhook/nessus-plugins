#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139748);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2020-16287",
    "CVE-2020-16288",
    "CVE-2020-16289",
    "CVE-2020-16290",
    "CVE-2020-16291",
    "CVE-2020-16292",
    "CVE-2020-16293",
    "CVE-2020-16294",
    "CVE-2020-16295",
    "CVE-2020-16296",
    "CVE-2020-16297",
    "CVE-2020-16298",
    "CVE-2020-16299",
    "CVE-2020-16300",
    "CVE-2020-16301",
    "CVE-2020-16302",
    "CVE-2020-16303",
    "CVE-2020-16304",
    "CVE-2020-16305",
    "CVE-2020-16306",
    "CVE-2020-16307",
    "CVE-2020-16308",
    "CVE-2020-16309",
    "CVE-2020-16310"
  );
  script_xref(name:"IAVB", value:"2020-B-0046-S");

  script_name(english:"Artifex Ghostscript 9.50 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows host is 9.50. It is, therefore, affected 
by multiple vulnerabilities:

  - A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. (CVE-2020-16302)

  - A use-after-free vulnerability in xps_finish_image_path() in devices/vector/gdevxps.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted PDF file. (CVE-2020-16303)

  - A buffer overflow vulnerability in image_render_color_thresh() in base/gxicolor.c of Artifex Software
    GhostScript v9.50 allows a remote attacker to escalate privileges via a crafted eps file. (CVE-2020-16304)

Additionally, the version of Artifex Ghostscript installed is affected by multiple buffer overflow vulnerabilities which
could allow an attacker to cause a denial of service via a crafted file.");
  script_set_attribute(attribute:"see_also", value:"https://www.ghostscript.com/Ghostscript_9.51.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Artifex Ghostscript 9.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include('vcf.inc');

app = 'Ghostscript';

constraints = [{'min_version' : '9.50', 'fixed_version' : '9.51'}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

