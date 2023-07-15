##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-015.
#
# @DEPRECATED@
#
# Disabled on 2022/05/02. Deprecated by al2_ALASDOCKER-2022-015.nasl (plugin ID 160407)
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158591);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2022-23648");
  script_xref(name:"ALAS", value:"2022-015");

  script_name(english:"Amazon Linux 2 : containerd (ALAS-2022-015) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated following detection of an issue with overlapping filenames. 
Deprecated by al2_ALASDOCKER-2022-015.nasl (plugin ID 160407)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASDOCKER-2022-015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23648.html");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23648");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:containerd-stress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}
exit(0, 'This plugin has been deprecated. Use al2_ALASDOCKER-2022-015.nasl (plugin ID 160407) instead.');
