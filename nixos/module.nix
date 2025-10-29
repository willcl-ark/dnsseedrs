{ config
, lib
, pkgs
, ...
}:
with lib; let
  cfg = config.services.dnsseedrs;
  dnsCfg = config.services.dnsseedrs-dns;

  # DNSSEC submodule
  dnssecOptions = {
    options = {
      enable = mkEnableOption "DNSSEC signing for this instance";

      autoGenerate = mkOption {
        type = types.bool;
        default = true;
        description = "Automatically generate DNSSEC keys if they don't exist.";
      };

      algorithm = mkOption {
        type = types.enum [ "ECDSAP256SHA256" "ED25519" ];
        default = "ECDSAP256SHA256";
        description = "DNSSEC key algorithm to use.";
      };

      keyDir = mkOption {
        type = types.str;
        default = "dnssec-keys";
        description = "Directory for DNSSEC keys (relative to dataDir).";
      };
    };
  };

  # DNS proxy configuration
  dnsProxyOptions = {
    enable = mkEnableOption "DNS forwarding proxy for dnsseedrs instances";

    implementation = mkOption {
      type = types.enum [ "coredns" ];
      default = "coredns";
      description = "DNS server implementation to use for forwarding.";
    };

    port = mkOption {
      type = types.port;
      default = 53;
      description = "Port to bind the DNS proxy to.";
    };

    upstreamResolvers = mkOption {
      type = types.listOf types.str;
      default = [ "1.1.1.1" "8.8.8.8" ];
      description = "Upstream DNS resolvers for non-seed domains.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open firewall ports for the DNS proxy.";
    };

    bind = mkOption {
      type = types.listOf types.str;
      default = [ "0.0.0.0" "::" ];
      description = "IP addresses to bind the DNS proxy to.";
    };
  };

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

      dnssec = mkOption {
        type = types.submodule dnssecOptions;
        default = { };
        description = "DNSSEC configuration.";
      };

      localPort = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "Local port for this instance when using DNS proxy. Overrides bind addresses.";
      };
    };
  };

  # Generate systemd service for an instance
  mkInstanceService = name: instanceCfg:
    let
      # Determine bind addresses
      bindAddresses =
        if instanceCfg.localPort != null
        then [ "udp://127.0.0.1:${toString instanceCfg.localPort}" "tcp://127.0.0.1:${toString instanceCfg.localPort}" ]
        else instanceCfg.bind;

      # DNSSEC keys path
      dnssecKeysPath =
        if instanceCfg.dnssec.enable
        then "${instanceCfg.dataDir}/${instanceCfg.dnssec.keyDir}"
        else if instanceCfg.dnssecKeys != null
        then toString instanceCfg.dnssecKeys
        else null;

      args =
        [
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
        ]
        ++ optionals instanceCfg.disableIPv4 [ "--no-ipv4" ]
        ++ optionals instanceCfg.disableIPv6 [ "--no-ipv6" ]
        ++ optionals instanceCfg.cjdnsReachable [ "--cjdns-reachable" ]
        ++ concatMap (seed: [ "--seednode" seed ]) instanceCfg.seedNodes
        ++ concatMap (bind: [ "--bind" bind ]) bindAddresses
        ++ optionals (dnssecKeysPath != null) [ "--dnssec-keys" dnssecKeysPath ]
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
  options = {
    services.dnsseedrs = mkOption {
      type = types.attrsOf (types.submodule instanceOptions);
      default = { };
      description = "dnsseedrs instances configuration.";
    };

    services.dnsseedrs-dns = mkOption {
      type = types.submodule { options = dnsProxyOptions; };
      default = { };
      description = "DNS proxy configuration for dnsseedrs instances.";
    };
  };

  # DNSSEC key generation function
  mkDnssecKeygenService = name: instanceCfg: {
    description = "Generate DNSSEC keys for dnsseedrs ${name}";
    before = [ "dnsseedrs-${name}.service" ];
    wantedBy = [ "dnsseedrs-${name}.service" ];

    serviceConfig = {
      Type = "oneshot";
      User = instanceCfg.user;
      Group = instanceCfg.group;
      WorkingDirectory = instanceCfg.dataDir;
      RemainAfterExit = true;
    };

    script =
      let
        keyDir = "${instanceCfg.dataDir}/${instanceCfg.dnssec.keyDir}";
        algorithm =
          if instanceCfg.dnssec.algorithm == "ECDSAP256SHA256"
          then "13"
          else "15";
      in
      ''
        mkdir -p "${keyDir}"
        cd "${keyDir}"

        # Check if keys already exist
        if ! ls K${instanceCfg.seedDomain}.+${algorithm}+*.key 2>/dev/null; then
          echo "Generating DNSSEC keys for ${instanceCfg.seedDomain}..."
          ${pkgs.bind}/bin/dnssec-keygen -a ${algorithm} -b 256 "${instanceCfg.seedDomain}"
          echo "DNSSEC keys generated in ${keyDir}"
          echo "Please configure your DNS provider with the following DS records:"
          for keyfile in K${instanceCfg.seedDomain}.+${algorithm}+*.key; do
            if [ -f "$keyfile" ]; then
              ${pkgs.bind}/bin/dnssec-dsfromkey "$keyfile"
            fi
          done
        else
          echo "DNSSEC keys already exist for ${instanceCfg.seedDomain}"
        fi
      '';
  };

  # CoreDNS configuration generator
  mkCoreDnsConfig =
    let
      instanceForwardings = concatStringsSep "\n" (mapAttrsToList
        (
          name: instanceCfg:
            let
              port =
                if instanceCfg.localPort != null
                then instanceCfg.localPort
                else 5353;
            in
            ''
              ${instanceCfg.seedDomain}:${toString dnsCfg.port} {
                  bind ${concatStringsSep " " dnsCfg.bind}
                  forward . 127.0.0.1:${toString port}
                  log
              }
            ''
        )
        enabledInstances);
    in
    ''
      ${instanceForwardings}

      .:${toString dnsCfg.port} {
          bind ${concatStringsSep " " dnsCfg.bind}
          forward . ${concatStringsSep " " dnsCfg.upstreamResolvers}
          log
      }
    '';

  config = mkMerge [
    (mkIf (enabledInstances != { }) {
      # Create users and groups for each enabled instance
      users.users =
        mapAttrs'
          (
            name: instanceCfg:
              nameValuePair instanceCfg.user {
                isSystemUser = true;
                group = instanceCfg.group;
                home = instanceCfg.dataDir;
                createHome = false;
                description = "dnsseedrs ${name} user";
              }
          )
          enabledInstances;

      users.groups =
        mapAttrs'
          (
            name: instanceCfg:
              nameValuePair instanceCfg.group { }
          )
          enabledInstances;

      # Create systemd services for each enabled instance
      systemd.services =
        mapAttrs'
          (
            name: instanceCfg:
              nameValuePair "dnsseedrs-${name}" (mkInstanceService name instanceCfg)
          )
          enabledInstances
        // optionalAttrs (any (instanceCfg: instanceCfg.dnssec.enable && instanceCfg.dnssec.autoGenerate) (attrValues enabledInstances))
          (mapAttrs'
            (
              name: instanceCfg:
                nameValuePair "dnsseedrs-${name}-dnssec-keys" (mkDnssecKeygenService name instanceCfg)
            )
            (filterAttrs (name: instanceCfg: instanceCfg.dnssec.enable && instanceCfg.dnssec.autoGenerate) enabledInstances));

      # Ensure data directories exist with correct permissions
      systemd.tmpfiles.rules = flatten (mapAttrsToList
        (name: instanceCfg:
          [
            "d ${instanceCfg.dataDir} 0750 ${instanceCfg.user} ${instanceCfg.group} - -"
          ]
          ++ optionals instanceCfg.dnssec.enable [
            "d ${instanceCfg.dataDir}/${instanceCfg.dnssec.keyDir} 0750 ${instanceCfg.user} ${instanceCfg.group} - -"
          ])
        enabledInstances);
    })

    # DNS proxy service configuration
    (mkIf dnsCfg.enable {
      services.coredns = {
        enable = true;
        config = mkCoreDnsConfig;
      };

      # Open firewall ports for DNS proxy
      networking.firewall = mkIf dnsCfg.openFirewall {
        allowedTCPPorts = [ dnsCfg.port ];
        allowedUDPPorts = [ dnsCfg.port ];
      };

      # Ensure CoreDNS package is available
      environment.systemPackages = [ pkgs.coredns ];
    })

    # DNSSEC helper script
    (mkIf (any (instanceCfg: instanceCfg.dnssec.enable) (attrValues enabledInstances)) {
      environment.systemPackages = [
        (pkgs.writeScriptBin "dnsseedrs-show-ds-records" (builtins.readFile ./show-ds-records.sh))
        pkgs.bind # For dnssec-dsfromkey command
      ];
    })
  ];
}
