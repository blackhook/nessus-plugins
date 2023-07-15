#%NASL_MIN_LEVEL 80900
##
#
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/01/27. Deprecated by drupal_10_0_2.nasl.
##

include('compat.inc');

if (description)
{
  script_id(170156);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_name(english:"Drupal 9.4.x < 9.4.10 / 9.5.x < 9.5.2 / 10.0.x < 10.0.2 Drupal Vulnerability (SA-CORE-2023-001) (Deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 9.4.x prior to 9.4.10
or 9.5.x prior to 9.5.2 or 10.0.x prior to 10.0.2. It is, therefore, affected by a vulnerability.

  - The Media Library module does not properly check entity access in some circumstances. This may result in
    users with access to edit content seeing metadata about media items they are not authorized to access. The
    vulnerability is mitigated by the fact that the inaccessible media will only be visible to users who can
    already edit content that includes a media reference field. This advisory is not covered by Drupal
    Steward. (SA-CORE-2023-001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated and replaced by drupal_10_0_2.nasl (plugin ID 170730).");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2023-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/10.0.2");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.4.10");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.5.2");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2021-06-29");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/steward");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use drupal_10_0_2.nasl (plugin ID 170730) instead.');
