##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/02/11. Retracted by vendor. 
##

include('compat.inc');

if (description)
{
  script_id(146305);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/11");

  script_cve_id("CVE-2020-36158");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2021-9041) (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 / 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2021-9041 advisory.

  - mwifiex_cmd_802_11_ad_hoc_start in drivers/net/wireless/marvell/mwifiex/join.c in the Linux kernel through
    5.10.4 might allow remote attackers to execute arbitrary code via a long SSID value, aka CID-5c455c5ab332.
    (CVE-2020-36158)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This advisory was deprecated by OracleLinux. See related links.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9041.html");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2021-February/010841.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36158");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.54.1.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-118.54.1.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. The advisory was retracted by the vendor.");
