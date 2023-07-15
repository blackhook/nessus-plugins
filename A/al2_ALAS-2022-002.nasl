##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-002.
#
# @DEPRECATED
#
# Deisabled on 2022/05/02. Deprecated by al2_ALASCORRETTO8-2022-002.nasl (160405)
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160314);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id(
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21476",
    "CVE-2022-21496"
  );
  script_xref(name:"IAVA", value:"2022-A-0170-S");
  script_xref(name:"ALAS", value:"2022-002");

  script_name(english:"Amazon Linux 2 : java-1.8.0-amazon-corretto (ALAS-2022-002) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated following detection of an issue with overlapping filenames. 
It has been replaced by al2_ALASCORRETTO8-2022-002.nasl (plugin ID 160405).");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASCORRETTO8-2022-002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21426.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21434.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21443.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21476.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-21496.html");
  script_set_attribute(attribute:"solution", value:
"N/A");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-amazon-corretto-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}
exit(0, 'This plugin has been deprecated, use al2_ALASCORRETTO8-2022-002.nasl (plugin ID 160405) instead.');
