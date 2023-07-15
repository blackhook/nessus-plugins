##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9150.
#
# Disabled on 2021/04/28. Use oraclelinux_ELSA-2021-9137.nasl
##

include('compat.inc');

if (description)
{
  script_id(148258);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2020-1971");

  script_name(english:"Oracle Linux 6 : openssl (ELSA-2021-9150) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated, please use oraclelinux_ELSA-2021-9137.nasl instead.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9150.html");
  script_set_attribute(attribute:"solution", value:
"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1971");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}
exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2021-9137.nasl instead.");
