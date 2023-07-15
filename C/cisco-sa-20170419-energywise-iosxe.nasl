#TRUSTED 8206f570529ff9a1a2066af7eb7b2e0ca910fe98eee7399d6b4fc708311afe73de128ce5304d3c1ba091667de44834ac6cf26e22de02cc018d34dce4bcd64a399e1311fa47f3261c81f28861a37681b4ab3a05c9ac27e2723d071511683e36af378b8ef75c45349a1918c4d43c712df12b026a3a26c486d4e376dae53250362f19d45da663f7ad2ac9a2b33e5e6ede91e121fc32c82a8bccc4da9fcdd73999623e81d8ae9d0bee7e399dc1645b3ab5381f7c1ae11f1e881a4914972ffde92d02a4af500c75c0405c2b626e4b8a743d51c0453f142ec0a7b4b154bc779a646841ead10cd00d165683f0d7be52e2b80813df4725361315ffae713f1a303041bf46090efe90962c2f8fceb75ea62a5d730574a5522b9b95149ffb35efa7add802e45c7720e6ac68509758573aed93b1faa8c17d0fd687145f0fdebaaad3703d91ccc9ed923204db41301430d4bcbee113523fb3a9834f08fb563033a3e323d21afcf6ba870ef2ac77ea1fb7b8f8bd650af7032fb6647bb277563ef279789b6383635e75af5e05ddd7221eabbf7d95237faf0abd02b8cdd19c470e81c19108835f05d085a37e47672c9a9c591c89c336890304c734c76378b0b2ad8134995b5f13cece7fc4fdfe61b665cb230e9f85ac91f7a0372fc589050df8b59dc62359293532b6e0fee3006abd22fb8a5edab3a473b95896f019c31da1f22ba50d77da2c03bc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99688);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2017-3860",
    "CVE-2017-3861",
    "CVE-2017-3862",
    "CVE-2017-3863"
  );
  script_bugtraq_id(97935);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut47751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut50727");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu76493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-energywise");

  script_name(english:"Cisco IOS XE EnergyWise DoS (cisco-sa-20170419-energywise)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by multiple buffer overflow
conditions due to improper parsing of EnergyWise packets. An
unauthenticated, remote attacker can exploit these, by sending
specially crafted IPv4 EnergyWise packets to the device, to cause a
denial of service condition. Note that IPv6 packets cannot be used to
exploit these issues and that the EnergyWise feature is not enabled by
default on Cisco XE devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2ebdad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur29331");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut47751");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut50727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu76493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170419-energywise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.7.7S",
  "3.2.0XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.10.4S",
  "3.10.8aS",
  "3.10.9S",
  "3.12.0aS",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.15.2xbS",
  "3.15.4S",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.5.8SQ",
  "3.16.1S",
  "3.16.0bS",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.2.1",
  "16.2.2",
  "3.8.0E",
  "3.18.3vS",
  "3.18.3bSP",
  "16.7.1b",
  "16.10.1",
  "16.11.1",
  "16.12.1",
  "16.13.1",
  "16.14.1",
  "16.15.1");

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['energywise'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCur29331, CSCut47751, CSCut50727, and CSCuu76493",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
