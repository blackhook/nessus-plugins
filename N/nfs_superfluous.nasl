#
# (C) Tenable Network Security, Inc.
#

#
# Get the export list of the remote host and
# warns the user if a NFS share is exported to the
# world.

include( 'compat.inc' );

if(description)
{
  script_id(42255);
  script_version ("1.4");

  script_cve_id("CVE-1999-0548");

  script_name(english: "NFS Server Superfluous");
  script_summary(english: "Checks if the NFS server isn't exporting anything");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host is running an unnecessary service."
  );

  script_set_attribute( attribute:'description', value:
"The remote NFS server is not exporting any shares.  Running an
unused service unnecessarily increases the attack surface of the
remote host."  );

  script_set_attribute(
    attribute:'solution',
    value:"Disable this service."
  );

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the issue by Tenable.");

  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/26"
  );

 script_cvs_date("Date: 2019/10/04 16:48:26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2019 Tenable Network Security, Inc.");
  script_family(english: "RPC");
  script_dependencie("showmount.nasl");
  script_require_keys("nfs/proto", "nfs/noshares");
  exit(0);
}

include("misc_func.inc");

proto = get_kb_item("nfs/proto");

if (get_kb_item("nfs/noshares"))
  security_note(port:2049, proto:proto);
