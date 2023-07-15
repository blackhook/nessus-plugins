##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-001.
#
# @DEPRECATED@
#
# Disabled on 2022/05/02. Deprecated by al2_ALASCORRETTO8-2021-001.nasl (plugin ID 160410)
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156175);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"ALAS", value:"2021-001");

  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Amazon Linux 2 : java-1.8.0-amazon-corretto (ALAS-2021-001) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated following detection of an issue with overlapping filenames. 
Deprecated by al2_ALASCORRETTO8-2021-001.nasl (plugin ID 160410)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASCORRETTO8-2021-001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-44228.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-45046.html");
  script_set_attribute(attribute:"solution", value:
"NA");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}
exit(0, 'This plugin has been deprecated. Use al2_ALASCORRETTO8-2021-001.nasl (plugin ID 160410) instead.');
