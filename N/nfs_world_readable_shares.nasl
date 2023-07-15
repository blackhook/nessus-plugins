#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(42256);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/05");

  script_name(english:"NFS Shares World Readable");
  script_summary(english:"Checks if host-based ACLs are being used.");

  script_set_attribute(attribute:'synopsis', value:
"The remote NFS server exports world-readable shares.");

  script_set_attribute( attribute:'description', value:
"The remote NFS server is exporting one or more shares without
restricting access (based on hostname, IP, or IP range).");

  script_set_attribute(attribute:'solution', value:
"Place the appropriate restrictions on all NFS shares.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Information Disclosure Score");

  script_set_attribute(attribute:'see_also', value:"http://www.tldp.org/HOWTO/NFS-HOWTO/security.html");


  script_set_attribute(attribute:"vuln_publication_date", value:"1985/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("showmount.nasl", "os_fingerprint.nasl");
  script_require_keys("nfs/proto", "nfs/share_acl");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

proto = get_kb_item_or_exit("nfs/proto");
list = get_kb_list_or_exit("nfs/share_acl");

shares = make_list(list);

if (netapp_check())
  exit(0, "This device appears to be a NetApp device with the root directory incorrectly shared. To avoid false positives, Nessus will not report on this accessible share unless 'Show potential false alarms' is enabled.");

report = '\nThe following shares have no access restrictions :\n\n';
vuln = FALSE;

foreach share (shares)
{
  share_info = split(share, sep:" ", keep:FALSE);
  acl = share_info[1];

  if (acl == "" || acl == "*")
  {
    report += '  ' + share + '\n';
    vuln = TRUE;
  }
}

if (vuln)
  security_report_v4(port:2049, proto:proto, severity:SECURITY_WARNING, extra:report);
else
  exit(0, "The NFS server doesn't have any world-readable shares.");


##
# Best effort check for NetApp devices which incorrectly reports '/' as accessible
#
# @return  bool  true  if NetApp device reports only '/' as accessible
#                false otherwise or if paranoid reporting is enabled 
##
function netapp_check()
{
  var os_kbs, os_kb, os_conf, os_value;

  if (report_paranoia == 2)
    return false;

  # disabling the following due to CS-34514
  # Only '/' along with the ACL should exist in list (i.e. '/  ' or '/ *')
  # if (len(shares) != 1 || shares[0] !~ "^/( |$)")
  #   return false;

  # Check if any of the target's OS fingerprints are for NetApp
  os_kbs = get_kb_list("Host/OS/*");
  os_kbs["Host/OS"] = get_kb_item("Host/OS");
  
  foreach os_kb (keys(os_kbs))
  {
    os_value = os_kbs[os_kb];
    if (os_value =~ "^NetApp")
    {
      os_conf  = get_kb_item(os_kb + "/Confidence");
      if (empty_or_null(os_conf)) continue;

      if (os_conf > 65)
        return true; 
    }
  }
}
