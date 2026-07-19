#!/usr/bin/python
from __future__ import annotations

from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible_common.core.plugins.module_utils.three_x_ui_xray import (
    ThreeXUIError,
    ThreeXUIXrayClient,
    reconcile_xray_config,
    write_backup,
)

DOCUMENTATION = r'''
---
module: three_x_ui_xray_apply
short_description: Reconcile panel-managed 3x-ui Xray template state
description:
  - Reads the panel-managed Xray template through the 3x-ui panel API.
  - Reconciles selected Xray template sections such as inbounds, reverse portals, and routing rules.
  - Saves the full Xray template back through the panel API only when drift is detected.
options:
  panel_url:
    description: Base URL of the 3x-ui panel, including any configured web base path.
    required: true
    type: str
  username:
    description: 3x-ui panel username.
    required: true
    type: str
  password:
    description: 3x-ui panel password.
    required: true
    type: str
  verify_tls:
    description: Whether to validate TLS certificates for panel API requests.
    type: bool
    default: false
  timeout:
    description: HTTP request timeout in seconds.
    type: int
    default: 20
  spec:
    description: Desired Xray template state.
    required: true
    type: dict
  restart:
    description: Whether to restart Xray after saving a changed template.
    type: bool
    default: true
  backup_path:
    description: Optional local path on the module execution host for the pre-change Xray template backup.
    type: str
    default: ""
supports_check_mode: true
author:
  - Infrastructure Automation Maintainers
'''

EXAMPLES = r'''
- name: Ensure a local SOCKS inbound exists
  ansible_common.core.three_x_ui_xray_apply:
    panel_url: https://hub.example.net:36588/panel-base
    username: "{{ vault_three_x_ui_username }}"
    password: "{{ vault_three_x_ui_password }}"
    spec:
      inbounds:
        - listen: 127.0.0.1
          port: 1080
          protocol: socks
          tag: managed-local-socks
          settings:
            auth: noauth
            udp: true
'''

RETURN = r'''
inbounds_added:
  description: Number of Xray inbounds added.
  returned: always
  type: int
inbounds_updated:
  description: Number of Xray inbounds updated.
  returned: always
  type: int
portals_added:
  description: Number of reverse portals added or updated.
  returned: always
  type: int
routes_added:
  description: Number of routing rules added or updated.
  returned: always
  type: int
'''


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "panel_url": {"type": "str", "required": True},
            "username": {"type": "str", "required": True, "no_log": True},
            "password": {"type": "str", "required": True, "no_log": True},
            "verify_tls": {"type": "bool", "default": False},
            "timeout": {"type": "int", "default": 20},
            "spec": {"type": "dict", "required": True},
            "restart": {"type": "bool", "default": True},
            "backup_path": {"type": "str", "default": ""},
        },
        supports_check_mode=True,
    )

    params = module.params
    try:
        client = ThreeXUIXrayClient(
            panel_url=params["panel_url"],
            username=params["username"],
            password=params["password"],
            verify_tls=params["verify_tls"],
            timeout=params["timeout"],
        )
        client.login()
        config = client.get_xray_config()
        before = deepcopy(config)
        result = reconcile_xray_config(config, params["spec"])
        changed = any(result.values())
        if changed and params["backup_path"] and not module.check_mode:
            write_backup(params["backup_path"], before)
        if changed and not module.check_mode:
            client.save_xray_config(config, restart=params["restart"])
        module.exit_json(changed=changed, check_mode=module.check_mode, **result)
    except ThreeXUIError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:
        module.fail_json(msg=f"unexpected 3x-ui Xray apply failure: {exc}")


if __name__ == "__main__":
    main()
