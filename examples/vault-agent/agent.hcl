# Vault Agent on a machine: logs in with the ergosum identity token and
# renders the machine's backup settings. The address is an example.

vault {
  address = "https://vault.example.com:8200"
  # ca_cert = "/etc/vault-agent/ca.pem"
}

auto_auth {
  method "jwt" {
    mount_path = "auth/machine"
    config = {
      role = "host"
      path = "/run/ergosum/token"
      # ergosumd replaces the token before it expires. The agent reads the
      # file again for every login, so it must not delete it.
      remove_jwt_after_reading = false
    }
  }
}

template {
  source      = "/etc/vault-agent/backup.env.ctmpl"
  destination = "/run/vault-agent/backup.env"
  perms       = "0600"
  error_on_missing_key = true
}
