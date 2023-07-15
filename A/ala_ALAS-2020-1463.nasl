##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020-12-23 due to Amazon pulling the previsouly published advisory.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1463.
##

include('compat.inc');

if (description)
{
  script_id(144461);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/23");

  script_cve_id("CVE-2020-14363");
  script_xref(name:"ALAS", value:"2020-1463");

  script_name(english:"Amazon Linux AMI : libX11 (ALAS-2020-1463) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2020-1463 advisory.

  - An integer overflow vulnerability leading to a double-free was found in libX11. This flaw allows a local
    privileged attacker to cause an application compiled with libX11 to crash, or in some cases, result in
    arbitrary code execution. The highest threat from this flaw is to confidentiality, integrity as well as
    system availability. (CVE-2020-14363)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated due to Amazon pulling the previously published advisory.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1463.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14363");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated due to Amazon pulling the previously published advisory.");
