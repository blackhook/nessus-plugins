##
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
# 
# Disabled on 2023/04/21 - Rejected CVE by NVD.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3158 and
# CentOS Errata and Security Advisory 2021:3158 respectively.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152664);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2021-31291");
  script_xref(name:"RHSA", value:"2021:3158");

  script_name(english:"CentOS 7 : exiv2 (CESA-2021:3158) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"** REJECT ** 
DO NOT USE THIS CANDIDATE NUMBER. 
ConsultIDs: CVE-2021-29457. 
Reason: This candidate is a duplicate of CVE-2021-29457. 
Notes: All CVE users should reference CVE-2021-29457 instead of this candidate. 
All references and descriptions in this candidate have been removed to prevent accidental usage.");;
  # https://lists.centos.org/pipermail/centos-announce/2021-August/048349.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03b31ca1");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exiv2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}

exit(0,'CVE-2021-31291 rejected in favor of CVE-2021-29457.');

