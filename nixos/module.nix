{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.dnsseedrs;

  instanceOptions = { name, ... }: {
    options = {
      enable = mkEnableOption "dnsseedrs instance for ${name}";

      package = mkOption {
        type = types.package;
        default = pkgs.dnsseedrs or (throw "dnsseedrs package not available. Add the dnsseedrs overlay to your nixpkgs.");
        description = "The dnsseedrs package to use.";
      };

      user = mkOption {
        type = types.str;
        default = "dnsseedrs-${name}";
        description = "User account under which dnsseedrs runs.";
      };

      group = mkOption {
        type = types.str;
        default = "dnsseedrs-${name}";
        description = "Group under which dnsseedrs runs.";
      };

      dataDir = mkOption {
        type = types.path;
        default = "/var/lib/dnsseedrs-${name}";
        description = "The data directory for dnsseedrs.";
      };

      seedNodes = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Initial seed nodes to connect to.";
      };

      dbFile = mkOption {
        type = types.str;
        default = "sqlite.db";
        description = "Database file name (relative to dataDir).";
      };

      dumpFile = mkOption {
        type = types.str;
        default = "seeds.txt";
        description = "Dump file name (relative to dataDir).";
      };

      disableIPv4 = mkOption {
        type = types.bool;
        default = false;
        description = "Disable IPv4 support.";
      };

      disableIPv6 = mkOption {
        type = types.bool;
        default = false;
        description = "Disable IPv6 support.";
      };

      cjdnsReachable = mkOption {
        type = types.bool;
        default = false;
        description = "Whether CJDNS is reachable.";
      };

      onionProxy = mkOption {
        type = types.str;
        default = "127.0.0.1:9050";
        description = "Onion proxy address.";
      };

      i2pProxy = mkOption {
        type = types.str;
        default = "127.0.0.1:4447";
        description = "I2P proxy address.";
      };

      threads = mkOption {
        type = types.ints.positive;
        default = 24;
        description = "Number of threads to use.";
      };

      bind = mkOption {
        type = types.listOf types.str;
        default = [ "udp://0.0.0.0:53" "tcp://0.0.0.0:53" ];
        description = "Protocol, IP, and port to bind to for serving DNS requests.";
      };

      dnssecKeys = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to directory containing DNSSEC keys produced by dnssec-keygen.";
      };

      seedDomain = mkOption {
        type = types.str;
        description = "The domain name for which this server will return results.";
      };

      serverName = mkOption {
        type = types.str;
        description = "The domain name of this server itself (what the NS record will point to).";
      };

      soaRname = mkOption {
        type = types.str;
        description = "The exact string to place in the rname field of the SOA record.";
      };

      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Additional command-line arguments to pass to dnsseedrs.";
      };
    };
  };

  # Generate systemd service for an instance
  mkInstanceService = name: instanceCfg:
    let
      args = [
        "--chain"
        "${name}"
        "--db-file"
        "${instanceCfg.dataDir}/${instanceCfg.dbFile}"
        "--dump-file"
        "${instanceCfg.dataDir}/${instanceCfg.dumpFile}"
        "--threads"
        (toString instanceCfg.threads)
        "--onion-proxy"
        instanceCfg.onionProxy
        "--i2p-proxy"
        instanceCfg.i2pProxy
      ] ++ optionals instanceCfg.disableIPv4 [ "--no-ipv4" ]
      ++ optionals instanceCfg.disableIPv6 [ "--no-ipv6" ]
      ++ optionals instanceCfg.cjdnsReachable [ "--cjdns-reachable" ]
      ++ concatMap (seed: [ "--seednode" seed ]) instanceCfg.seedNodes
      ++ concatMap (bind: [ "--bind" bind ]) instanceCfg.bind
      ++ optionals (instanceCfg.dnssecKeys != null) [ "--dnssec-keys" (toString instanceCfg.dnssecKeys) ]
      ++ [ instanceCfg.seedDomain instanceCfg.serverName instanceCfg.soaRname ]
      ++ instanceCfg.extraArgs;
    in
    {
      description = "DNS seed server for Bitcoin ${name} network";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "exec";
        User = instanceCfg.user;
        Group = instanceCfg.group;
        ExecStart = "${instanceCfg.package}/bin/dnsseedrs ${escapeShellArgs args}";
        WorkingDirectory = instanceCfg.dataDir;
        StateDirectory = "dnsseedrs-${name}";
        StateDirectoryMode = "0750";

        # Security settings
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;

        # Network access needed
        PrivateNetwork = false;

        # Capabilities for binding low dns port (optional)
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

        # Restart policy
        Restart = "always";
        RestartSec = "10s";
      };
    };

  enabledInstances = filterAttrs (name: cfg: cfg.enable) cfg;

in
{
  options.services.dnsseedrs = mkOption {
    type = types.attrsOf (types.submodule instanceOptions);
    default = { };
    description = "dnsseedrs instances configuration.";
  };

  config = mkIf (enabledInstances != { }) {
    # Create users and groups for each enabled instance
    users.users = mapAttrs'
      (name: instanceCfg:
        nameValuePair instanceCfg.user {
          isSystemUser = true;
          group = instanceCfg.group;
          home = instanceCfg.dataDir;
          createHome = false;
          description = "dnsseedrs ${name} user";
        }
      )
      enabledInstances;

    users.groups = mapAttrs'
      (name: instanceCfg:
        nameValuePair instanceCfg.group { }
      )
      enabledInstances;

    # Create systemd services for each enabled instance
    systemd.services = mapAttrs'
      (name: instanceCfg:
        nameValuePair "dnsseedrs-${name}" (mkInstanceService name instanceCfg)
      )
      enabledInstances;

    # Ensure data directories exist with correct permissions
    systemd.tmpfiles.rules = flatten (mapAttrsToList
      (name: instanceCfg: [
        "d ${instanceCfg.dataDir} 0750 ${instanceCfg.user} ${instanceCfg.group} - -"
      ])
      enabledInstances);

    # Open firewall ports if needed (commented out by default for security)
    # networking.firewall.allowedTCPPorts = flatten (mapAttrsToList
    #   (name: instanceCfg:
    #     map
    #       (bind:
    #         let
    #           parts = splitString ":" (removePrefix "tcp://" bind);
    #           port = toInt (last parts);
    #         in
    #         port
    #       )
    #       (filter (hasPrefix "tcp://") instanceCfg.bind)
    #   )
    #   enabledInstances);
    #
    # networking.firewall.allowedUDPPorts = flatten (mapAttrsToList
    #   (name: instanceCfg:
    #     map
    #       (bind:
    #         let
    #           parts = splitString ":" (removePrefix "udp://" bind);
    #           port = toInt (last parts);
    #         in
    #         port
    #       )
    #       (filter (hasPrefix "udp://") instanceCfg.bind)
    #   )
    #   enabledInstances);
  };
}
