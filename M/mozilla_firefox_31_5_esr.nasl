#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81520);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2015-0822",
    "CVE-2015-0827",
    "CVE-2015-0831",
    "CVE-2015-0833",
    "CVE-2015-0835",
    "CVE-2015-0836"
  );
  script_bugtraq_id(
    72742,
    72746,
    72747,
    72748,
    72755,
    72756
  );

  script_name(english:"Firefox ESR 31.x < 31.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR 31.x installed on the remote Windows host
is prior to 31.5. It is, therefore, affected by the following
vulnerabilities :

  - An information disclosure vulnerability exists related
    to the autocomplete feature that allows an attacker to
    read arbitrary files. (CVE-2015-0822)

  - An out-of-bounds read and write issue exists when
    processing invalid SVG graphic files. This allows an
    attacker to disclose sensitive information.
    (CVE-2015-0827)

  - A use-after-free issue exists when running specific web
    content with 'IndexedDB' to create an index, resulting
    in a denial of service condition or arbitrary code
    execution. (CVE-2015-0831)

  - An issue exists in the Mozilla updater in which DLL
    files in the current working directory or Windows
    temporary directories will be loaded, allowing the
    execution of arbitrary code. Note that hosts are only
    affected if the updater is not run by the Mozilla
    Maintenance Service. (CVE-2015-0833)

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2015-0835, CVE-2015-0836)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-16/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-19/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-24/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR 31.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0836");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'31.5', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
