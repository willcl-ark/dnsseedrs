# Example NixOS configuration for dnsseedrs with automated DNSSEC and DNS proxy

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    dnsseedrs.url = "github:achow101/dnsseedrs";
  };

  outputs = { nixpkgs, dnsseedrs, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        dnsseedrs.nixosModules.default
        {
          # Add the dnsseedrs overlay to get the package
          nixpkgs.overlays = [ dnsseedrs.overlays.default ];

          # Enable DNS proxy with automatic forwarding
          services.dnsseedrs-dns = {
            enable = true;
            openFirewall = true; # Opens port 53 for DNS
            upstreamResolvers = [ "1.1.1.1" "8.8.8.8" "9.9.9.9" ];
          };

          # Configure mainnet instance
          services.dnsseedrs.mainnet = {
            enable = true;

            # DNS configuration
            seedDomain = "seed.bitcoin.example.org";
            serverName = "ns.example.org";
            soaRname = "admin.example.org";

            # Use simplified local port - DNS proxy handles forwarding
            localPort = 5353;

            # Performance settings
            threads = 32;

            # Initial seed nodes
            seedNodes = [
              "seed.bitcoin.sipa.be:8333"
              "dnsseed.bluematt.me:8333"
              "seed.bitcoinstats.com:8333"
            ];

            # DNSSEC configuration
            dnssec = {
              enable = true;
              autoGenerate = true; # Automatically generate keys
              algorithm = "ECDSAP256SHA256";
            };
          };

          # Configure signet instance
          services.dnsseedrs.signet = {
            enable = true;

            # DNS configuration
            seedDomain = "signet.bitcoin.example.org";
            serverName = "ns.example.org";
            soaRname = "admin.example.org";

            # Use different port for signet
            localPort = 5454;

            # Fewer threads for signet
            threads = 16;

            # Signet seed nodes
            seedNodes = [
              "seed.signet.bitcoin.sprovoost.nl:38333"
            ];

            # DNSSEC for signet too
            dnssec = {
              enable = true;
              autoGenerate = true;
            };
          };

          # Optional: Configure testnet instance
          services.dnsseedrs.testnet = {
            enable = false; # Disabled by default

            seedDomain = "testnet.bitcoin.example.org";
            serverName = "ns.example.org";
            soaRname = "admin.example.org";
            localPort = 5455;
            threads = 16;

            dnssec.enable = true;
          };
        }
      ];
    };
  };
}

# After applying this configuration:
#
# 1. DNS proxy will automatically forward:
#    - seed.bitcoin.example.org:53 -> 127.0.0.1:5353 (mainnet)
#    - signet.bitcoin.example.org:53 -> 127.0.0.1:5454 (signet)
#    - Everything else -> upstream resolvers
#
# 2. DNSSEC keys will be automatically generated on first run
#
# 3. To view DS records for your DNS provider:
#    dnsseedrs-show-ds-records mainnet
#    dnsseedrs-show-ds-records signet
#    dnsseedrs-show-ds-records  # Shows all instances
#
# 4. Services will be available as:
#    systemctl status dnsseedrs-mainnet
#    systemctl status dnsseedrs-signet
#    systemctl status coredns
#
# 5. Logs can be viewed with:
#    journalctl -u dnsseedrs-mainnet
#    journalctl -u dnsseedrs-signet
#    journalctl -u coredns
