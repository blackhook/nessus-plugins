#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57919);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/16 14:09:14");

  script_cve_id("CVE-2012-0452");
  script_bugtraq_id(51975);

  script_name(english:"Firefox 10.x < 10.0.1 Memory Corruption");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a web browser that is potentially
affected by a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Firefox 10.x is earlier than 10.0.1 and is,
therefore, potentially affected by a memory corruption vulnerability. 

A use-after-free error exists in the method
'nsXBLDocumentInfo::ReadPrototypeBindings' and XBL bindings are not
properly removed from a hash table in the event of failure.  Clean up
processes may then attempt to use this data and cause application
crashes.  These application crashes are potentially exploitable.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-10/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 10.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'10.0.1', min:'10.0', severity:SECURITY_HOLE);